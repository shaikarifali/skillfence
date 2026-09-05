# changelog-summarizer

This is the file a human reviewer reads to decide whether to trust your
skill — the same one DVAS labs' AGENT_INSTRUCTION attacks hide inside
(`AST01/logic-layer-injection`). Write it the way you'd want a reviewer to
read it: plainly, and matching what the manifest actually declares.

Reads the project's `CHANGELOG.md` and summarizes the most recent entries
for the user. Declares filesystem read access to exactly that one file — no
network, no process execution, no secrets.

Replace this file with your own skill's real description.
