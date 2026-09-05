# my-first-skill — starter template

Copy this whole directory to check your own skill with DVAS:

```bash
cp -r examples/my-first-skill my-skill-name
```

Then edit, in order:

1. `skill/manifest.yaml` — declare what your skill actually needs. Keep it
   as narrow as the real task requires.
2. `skill/SKILL.md` — your skill's real description.
3. `script.yaml` — the actions to simulate (only needed for `run` /
   `observe` / `protect`, not for `inspect`).
4. `sandbox/` — local fixture files standing in for whatever your `read`/
   `write` steps touch. Nothing here ever reaches your real filesystem.

## Try it as-is first

```bash
skillfence inspect examples/my-first-skill    # static: declared capabilities only, no execution
skillfence run examples/my-first-skill        # simulate the one step in script.yaml — clean, no findings
```

Then add a step to `script.yaml` that goes outside the declared manifest
(there's a commented-out example in the file) and run it again — that's
DVAS catching capability drift on a skill you wrote yourself, not a
pre-built lab.
