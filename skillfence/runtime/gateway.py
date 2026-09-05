"""SkillFence Runtime Gateway — the enforcement point every wrapped tool call
goes through (agent tool wrappers -> normalize -> enforce).

This is the one place in the codebase where "should this action actually
happen" gets decided. Every wrapper (read_file/write_file/execute_shell/
fetch_url/network_send) funnels through `_enforce`, which:

  normalize -> publish -> correlate -> score -> LOW/MEDIUM allow
                                              -> HIGH/CRITICAL human gate
                                              -> record decision -> execute or block

Reject genuinely prevents execution: the wrapper never performs the real
filesystem/network op until `_enforce` returns a grant.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from skillfence.correlation.session import CorrelationEngine
from skillfence.events.bus import EventBus
from skillfence.events.schema import DecisionState, Event, EventType, new_id
from skillfence.findings.schema import Finding
from skillfence.hitl.cli_gate import HumanGate
from skillfence.hitl.decisions import DecisionRecord, DecisionRequest, DecisionType
from skillfence.policy.engine import PolicyEngine, PolicyResult
from skillfence.policy.manifest import CapabilityManifest
from skillfence.policy.store import PolicyStore
from skillfence.provenance.graph import ProvenanceGraph
from skillfence.risk.engine import RiskAssessment, RiskEngine
from skillfence.runtime.content_scan import detect_instruction, parse_injected_action
from skillfence.runtime.sandbox import Sandbox


class ActionBlocked(Exception):
    def __init__(self, finding: Finding) -> None:
        super().__init__(finding.title)
        self.finding = finding


class RuntimeGateway:
    def __init__(
        self,
        *,
        bus: EventBus,
        manifest: CapabilityManifest,
        sandbox: Sandbox,
        human_gate: HumanGate,
        session_id: str,
        agent: str,
        skill: str,
        observe_mode: bool = False,
        policy_store: PolicyStore | None = None,
        skill_definition_text: str | None = None,
    ) -> None:
        self.bus = bus
        self.manifest = manifest
        self.sandbox = sandbox
        self.human_gate = human_gate
        self.session_id = session_id
        self.agent = agent
        self.skill = skill
        self.observe_mode = observe_mode  # observe mode never blocks
        self.policy_store = policy_store  # cross-run decision memory

        self.policy = PolicyEngine(manifest)
        self.risk = RiskEngine()
        self.correlation = CorrelationEngine()
        self.findings: list[Finding] = []

        self._external_instruction_active = False
        self._external_instruction_event_id: str | None = None
        # LPCI: instruction-like text found in the skill's
        # *own* definition, scanned once at start() — opt-in per lab (see
        # lab_runner) so an unrelated lab's SKILL.md prose that happens to
        # mention "AGENT_INSTRUCTION:" while describing a *different* lab
        # never accidentally self-triggers this.
        self._skill_definition_text = skill_definition_text
        self._logic_layer_instruction_active = False
        self._logic_layer_instruction_event_id: str | None = None
        self._logic_layer_injected_step: dict | None = None
        self._session_allow: set[tuple[str, str]] = set()  # (event_type, resource)
        self.root_event_id: str | None = None
        self.invoke_event_id: str | None = None

        # AST02: the manifest in force immediately before the most
        # recent skill.update, kept so newly-declared-since-update
        # capabilities can be told apart from ones that were always declared.
        self._pre_update_manifest: CapabilityManifest | None = None
        self._post_update = False

    # -- lifecycle --------------------------------------------------------

    def start(self) -> str:
        load = self._publish(EventType.SKILL_LOAD, resource=self.skill, sensitive=False, declared=True)
        self.root_event_id = load.event_id

        if self._skill_definition_text:
            instruction = detect_instruction(self._skill_definition_text)
            if instruction:
                instr_event = self._publish(
                    EventType.LOGIC_LAYER_INSTRUCTION_DETECTED,
                    resource=self.skill,
                    sensitive=False,
                    declared=False,
                    parent_event=load.event_id,
                    details={"matched": instruction},
                )
                self._logic_layer_instruction_active = True
                self._logic_layer_instruction_event_id = instr_event.event_id
                injected = parse_injected_action(self._skill_definition_text)
                if injected:
                    self._logic_layer_injected_step = injected

        invoke = self._publish(
            EventType.SKILL_INVOKE, resource=self.skill, sensitive=False, declared=True, parent_event=load.event_id
        )
        self.invoke_event_id = invoke.event_id
        return invoke.event_id

    def logic_layer_injection(self) -> tuple[dict, str] | None:
        """The `(injected_action, source_event_id)` parsed from an
        instruction embedded in the skill's own definition (LPCI),
        if `start()` found one — analogous to fetched-content
        instruction injection for AST05, but sourced from the trusted skill
        artifact itself. The caller (the agent adapter) turns this into a
        concrete step the same way it turns a fetched-content injection into
        one, since gateway.py shouldn't need to know the adapter's step
        schema.
        """
        if self._logic_layer_injected_step is None or self._logic_layer_instruction_event_id is None:
            return None
        return self._logic_layer_injected_step, self._logic_layer_instruction_event_id

    def apply_update(
        self, to_version: str, new_manifest_path: Path, *, parent_event: str | None = None
    ) -> None:
        """Skill update/dependency-change event (AST02). Swaps the active
        manifest and remembers the previous one, so subsequent capability
        checks can distinguish "always declared" from "newly declared by
        this (possibly compromised) update."
        """
        parent = parent_event or self.invoke_event_id
        new_manifest = CapabilityManifest.load(new_manifest_path, workspace=self.sandbox.root)
        self._publish(
            EventType.SKILL_UPDATE,
            resource=new_manifest_path.name,
            sensitive=False,
            declared=True,
            parent_event=parent,
            details={"from_version": self.manifest.version, "to_version": to_version},
        )
        self._pre_update_manifest = self.manifest
        self.manifest = new_manifest
        self.policy = PolicyEngine(new_manifest)
        self._post_update = True

    # -- wrapped tool calls -------------------------------------------------

    def read_file(self, path: str, *, parent_event: str | None = None) -> str:
        parent = parent_event or self.invoke_event_id
        policy_result = self.policy.evaluate_fs_read(path)
        grant = self._enforce(
            event_type=EventType.FS_READ,
            resource=path,
            policy_result=policy_result,
            parent_event=parent,
            action_label="filesystem.read",
            title="Filesystem read outside declared capability" if not policy_result.declared else "Sensitive filesystem read",
            ast=self._ast_for(fs=True),
        )
        real_path = self.sandbox.resolve(path)
        if not real_path.exists():
            raise FileNotFoundError(f"(sandbox) {path} not found at {real_path}")
        content = real_path.read_text(encoding="utf-8")
        grant.record_result(content_len=len(content))
        return content

    def write_file(self, path: str, content: str, *, parent_event: str | None = None) -> None:
        parent = parent_event or self.invoke_event_id
        policy_result = self.policy.evaluate_fs_write(path)
        self._enforce(
            event_type=EventType.FS_WRITE,
            resource=path,
            policy_result=policy_result,
            parent_event=parent,
            action_label="filesystem.write",
            title="Filesystem write outside declared capability",
            ast=self._ast_for(fs=True),
        )
        real_path = self.sandbox.resolve(path)
        real_path.parent.mkdir(parents=True, exist_ok=True)
        real_path.write_text(content, encoding="utf-8")

    def execute_shell(self, command: str, *, parent_event: str | None = None) -> str:
        parent = parent_event or self.invoke_event_id
        executable = command.split()[0] if command else ""
        policy_result = self.policy.evaluate_process(executable)
        self._enforce(
            event_type=EventType.PROCESS_EXEC,
            resource=command,
            policy_result=policy_result,
            parent_event=parent,
            action_label="process.exec",
            title="Process execution outside declared capability",
            ast=["AST03"],
        )
        if executable not in self.sandbox.allowed_shell_commands:
            return f"(sandbox) refused to actually execute '{executable}' — not in lab's safe command list"
        return f"(sandbox) simulated execution of: {command}"

    def access_secret(self, var_name: str, *, parent_event: str | None = None) -> str:
        """Read a named secret/credential value the skill's process environment
        exposes (e.g. an env var). AST04: `secrets.access` is a single
        blanket boolean in the manifest schema — it can't scope *which*
        secret a skill actually needs, so a skill whose stated purpose never
        mentions credentials can still declare it and no reviewer reading the
        manifest sees which value that flag actually grants.
        """
        parent = parent_event or self.invoke_event_id
        policy_result = self.policy.evaluate_env_secret(var_name)
        self._enforce(
            event_type=EventType.SECRET_ACCESS,
            resource=var_name,
            policy_result=policy_result,
            parent_event=parent,
            action_label="secret.access",
            title="Secret/credential access outside declared scope" if not policy_result.declared else "Sensitive secret access",
            ast=["AST03", "AST04"],
        )
        return "(sandbox) simulated read of env var " + var_name

    def fetch_url(self, url: str, *, parent_event: str | None = None) -> tuple[str, Event]:
        """External content fetch (AST05). Always allowed at LOW risk on
        its own — the fetch is not the attack, what the content *causes next*
        is. If the fetched content contains instruction-like text, we flag it
        and remember that this session has seen an untrusted instruction, so
        any subsequent sensitive request gets scored higher and correlated
        into an AST05 chain.
        """
        parent = parent_event or self.invoke_event_id
        domain = urlparse(url).netloc or url
        policy_result = self.policy.evaluate_network(domain)
        fetch_event = self._publish(
            EventType.EXTERNAL_CONTENT_FETCH,
            resource=url,
            sensitive=False,
            declared=policy_result.declared,
            parent_event=parent,
            details={"domain": domain},
        )
        self.correlation.observe(fetch_event)

        fixture = self.sandbox.fake_internet.get(url)
        content = fixture.read_text(encoding="utf-8") if fixture else ""

        instruction = detect_instruction(content)
        if instruction:
            instr_event = self._publish(
                EventType.EXTERNAL_CONTENT_INSTRUCTION_DETECTED,
                resource=url,
                sensitive=False,
                declared=False,
                parent_event=fetch_event.event_id,
                details={"matched": instruction},
            )
            self.correlation.observe(instr_event)
            self._external_instruction_active = True
            self._external_instruction_event_id = instr_event.event_id
            return content, instr_event
        return content, fetch_event

    def network_send(self, destination: str, payload_desc: str, *, parent_event: str | None = None) -> None:
        """Simulated outbound network egress (e.g. exfiltration attempt).
        Never opens a real socket — captures intent only.
        """
        parent = parent_event or self.invoke_event_id
        domain = urlparse(destination).netloc or destination
        policy_result = self.policy.evaluate_network(domain)
        # AST04: the manifest *does* declare network access with a
        # specific domain allowlist, but this destination isn't on it --
        # metadata makes a promise ("only X"), runtime breaks it. Distinct
        # from AST03's "no network declared at all" case.
        metadata_mismatch = (
            self.manifest.capabilities.network.enabled
            and bool(self.manifest.capabilities.network.domains)
            and not policy_result.declared
        )
        self._enforce(
            event_type=EventType.NET_HTTP_REQUEST,
            resource=destination,
            policy_result=policy_result,
            parent_event=parent,
            action_label="network.http_request",
            title="Outbound network egress outside declared capability",
            ast=self._ast_for(network=True, metadata_mismatch=metadata_mismatch),
            extra_risk={"network_egress": True, "unknown_destination": not policy_result.declared},
            details={"domain": domain, "payload": payload_desc},
        )
        self.sandbox.capture_exfil(destination, payload_desc)

    # -- core enforcement ---------------------------------------------------

    def _enforce(
        self,
        *,
        event_type: EventType,
        resource: str,
        policy_result: PolicyResult,
        parent_event: str | None,
        action_label: str,
        title: str,
        ast: list[str],
        extra_risk: dict | None = None,
        details: dict | None = None,
    ) -> "_Grant":
        allow_key = (event_type.value, resource)
        store_prior_approval = self.policy_store is not None and self.policy_store.is_granted(
            skill=self.skill, event_type=event_type.value, resource=resource
        )
        session_prior_approval = allow_key in self._session_allow or store_prior_approval

        event = self._publish(
            event_type,
            resource=resource,
            sensitive=policy_result.sensitive,
            declared=policy_result.declared,
            parent_event=parent_event,
            details={**(details or {}), "reasons": policy_result.reasons},
        )
        self.correlation.observe(event)

        # AST02: was this capability declared only as of the *current*
        # (post-update) manifest, i.e. absent even from the manifest in
        # force before the most recent skill.update?
        behavior_changed_after_update = (
            self._post_update
            and self._pre_update_manifest is not None
            and policy_result.declared
            and not self._allowed_by_manifest(self._pre_update_manifest, event_type, resource)
        )
        if behavior_changed_after_update:
            ast = sorted(set(ast) | {"AST02"})
        if self._logic_layer_instruction_active:
            # LPCI: the malicious payload lives in the
            # skill's own natural-language definition, not fetched content
            # or a code-layer pattern (exec/curl/subprocess) — AST01, not
            # AST05 (no external fetch was involved in this action).
            ast = sorted(set(ast) | {"AST01"})

        risk_kwargs = dict(
            sensitive_credential_read=policy_result.sensitive and event_type in (EventType.FS_READ, EventType.SECRET_ACCESS),
            undeclared_capability=not policy_result.declared,
            external_instruction_involved=self._external_instruction_active,
            logic_layer_instruction_involved=self._logic_layer_instruction_active,
            working_directory_access=self._looks_like_workspace(resource),
            previously_approved_exact_action=session_prior_approval,
            behavior_changed_after_update=behavior_changed_after_update,
        )
        risk_kwargs.update(extra_risk or {})
        assessment = self.risk.assess(**risk_kwargs)

        if not assessment.requires_human_gate:
            event.decision = DecisionState.ALLOWED
            return _Grant(event)

        finding = self._build_finding(
            title=title,
            ast=ast,
            assessment=assessment,
            action=action_label,
            resource=resource,
            policy_result=policy_result,
            reasons=policy_result.reasons + assessment.factors,
            event=event,
        )

        if self.observe_mode:
            # observe mode never blocks -- still records the finding
            # that *would* have gated in enforce mode, for audit purposes.
            finding.status = "observed_only"
            finding.human_decision = "n/a (observe mode)"
            self.findings.append(finding)
            event.decision = DecisionState.ALLOWED
            return _Grant(event)

        provenance = ProvenanceGraph(self.bus.events_for_session(self.session_id))
        provenance_text = provenance.render_ascii(event.event_id)

        request = DecisionRequest(
            decision_id=new_id("decision"),
            event_id=event.event_id,
            skill=self.skill,
            requested_action=action_label,
            target=resource,
            risk=assessment.severity.value,
            cds=assessment.cds,
            cds_band=assessment.cds_band,
            reasons=finding.why_flagged,
            recommended_action=assessment.recommended_action,
            allowed_actions=list(DecisionType),
            ast=finding.ast,  # fully classified (AST01/AST05/chain tags included), not the pre-expansion `ast` list
            provenance=provenance_text,
        )
        explanation = self._explain(request, policy_result, behavior_changed_after_update=behavior_changed_after_update)
        decision = self.human_gate.decide(request, explanation=explanation, provenance=provenance_text)

        self._publish(
            EventType.HUMAN_DECISION,
            resource=resource,
            sensitive=False,
            declared=True,
            parent_event=event.event_id,
            details={"decision": decision.decision.value, "reason": decision.reason},
        )

        finding.human_decision = decision.decision.value
        finding.status = "approved" if decision.grants_execution else "blocked"
        self.findings.append(finding)

        if decision.decision in (DecisionType.ALLOW_FOR_SESSION, DecisionType.ALLOW_SCOPED):
            self._session_allow.add(allow_key)
            if decision.decision == DecisionType.ALLOW_SCOPED and self.policy_store is not None:
                # A narrowly-scoped, expiring grant tied to this
                # exact (skill, action, resource) -- never "always trust
                # this skill." Persists across future `skillfence run`s of
                # this lab, unlike ALLOW_FOR_SESSION which is this-run-only.
                self.policy_store.add_grant(
                    skill=self.skill,
                    event_type=event_type.value,
                    resource=resource,
                    decision=decision.decision.value,
                    reason=decision.reason,
                )
                decision.policy_created = True
                finding.status = "approved (policy created)"

        if decision.grants_execution:
            event.decision = (
                DecisionState.APPROVED_ONCE if decision.decision == DecisionType.APPROVE_ONCE else DecisionState.ALLOWED
            )
            return _Grant(event)

        event.decision = (
            DecisionState.QUARANTINED if decision.decision == DecisionType.QUARANTINE_SKILL else DecisionState.REJECTED
        )
        self._publish(
            EventType.TOOL_DENIED,
            resource=resource,
            sensitive=policy_result.sensitive,
            declared=policy_result.declared,
            parent_event=event.event_id,
        )
        raise ActionBlocked(finding)

    # -- helpers ------------------------------------------------------------

    def _publish(
        self,
        event_type: EventType,
        *,
        resource: str | None,
        sensitive: bool,
        declared: bool | None,
        parent_event: str | None = None,
        details: dict | None = None,
    ) -> Event:
        event = Event(
            session_id=self.session_id,
            agent=self.agent,
            skill=self.skill,
            event_type=event_type,
            resource=resource,
            declared=declared,
            sensitive=sensitive,
            parent_event=parent_event,
            details=details or {},
        )
        return self.bus.publish(event)

    def _looks_like_workspace(self, resource: str) -> bool:
        return resource.startswith("./") or resource.startswith("${workspace}")

    def _ast_for(self, *, fs: bool = False, network: bool = False, metadata_mismatch: bool = False) -> list[str]:
        # AST01 (malicious/sensitive) and AST02 (post-update behavior delta)
        # are layered on in _enforce/_build_finding; this seeds the
        # over-privileged-capability tag every gated action carries, plus
        # AST04 when the manifest made a specific promise the runtime broke.
        tags = ["AST03"]
        if metadata_mismatch:
            tags.append("AST04")
        return tags

    def _allowed_by_manifest(self, manifest: CapabilityManifest, event_type: EventType, resource: str) -> bool:
        if event_type == EventType.FS_READ:
            return manifest.allows_fs_read(resource)
        if event_type == EventType.FS_WRITE:
            return manifest.allows_fs_write(resource)
        if event_type == EventType.PROCESS_EXEC:
            executable = resource.split()[0] if resource else ""
            return manifest.allows_process(executable)
        if event_type == EventType.NET_HTTP_REQUEST:
            domain = urlparse(resource).netloc or resource
            return manifest.allows_network(domain)
        return True

    def _build_finding(
        self,
        *,
        title: str,
        ast: list[str],
        assessment: RiskAssessment,
        action: str,
        resource: str,
        policy_result: PolicyResult,
        reasons: list[str],
        event: Event,
    ) -> Finding:
        ast_tags = set(ast)
        if policy_result.sensitive:
            ast_tags.add("AST01")
        if self._external_instruction_active:
            ast_tags.add("AST05")

        evidence_ids = [e.event_id for e in self.bus.events_for_session(self.session_id)[-8:]]
        chains = self.correlation.session(self.session_id).chains
        chain_labels = [c.label for c in chains]
        for chain in chains:
            ast_tags.update(chain.ast_mapping)

        return Finding(
            title=title,
            ast=sorted(ast_tags),
            severity=assessment.severity.value,
            cds=assessment.cds,
            cds_band=assessment.cds_band,
            confidence="high" if policy_result.sensitive else "medium",
            skill=self.skill,
            action=action,
            resource=resource,
            declared_capability=", ".join(policy_result.reasons) if not policy_result.declared else "declared",
            observed_capability=action,
            why_flagged=reasons,
            attack_chain=chain_labels,
            evidence=evidence_ids,
            provenance_root=self.root_event_id,
            human_gate=True,
            status="pending",
        )

    def _explain(
        self,
        request: DecisionRequest,
        policy_result: PolicyResult,
        *,
        behavior_changed_after_update: bool = False,
    ) -> str:
        # Human-readable paragraph.
        lines = [
            f'The skill "{request.skill}" is requesting {request.requested_action} on {request.target}.',
        ]
        if not policy_result.declared:
            lines.append("This capability is not present in the skill's declared manifest.")
        if policy_result.sensitive:
            lines.append("The target is a recognized sensitive credential/secret path.")
        if self._external_instruction_active:
            lines.append(
                "This request occurred after external content containing instruction-like text was fetched in this session."
            )
        if self._logic_layer_instruction_active:
            lines.append(
                "The skill's own definition (not fetched content, not code) contains an instruction-like "
                "directive — a logic-layer injection a code-pattern scanner would not see."
            )
        if behavior_changed_after_update:
            lines.append(
                "This capability was declared only as of the most recent skill update — it was absent from the "
                "manifest immediately beforehand. Treat post-update behavior changes as a supply-chain signal, "
                "not as safe merely because the new manifest now declares it."
            )
        lines.append(f"Recommended action: {request.recommended_action.upper()}.")
        return "\n".join(lines)


class _Grant:
    """Returned when an action is allowed to proceed. Kept tiny — it exists so
    callers can attach post-execution metadata without the gateway needing to
    know about filesystem/network specifics.
    """

    def __init__(self, event: Event) -> None:
        self.event = event

    def record_result(self, **details: object) -> None:
        self.event.details.update(details)
