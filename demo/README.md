# Flagship demo

`flagship_demo.py` tells one attack path end to end against the bundled reference
API, offline and deterministically:

1. the attacker-controlled input (an issue comment),
2. the agent's legitimate authority (the support-agent boundaries),
3. the sequence of individually-permitted calls (read comment → register webhook
   → push),
4. the trust boundary crossed (untrusted text drives a caller-named webhook),
5. the harmful outcome (a private file's canary reaches the attacker host),
6. the proposed control (restrict outbound destinations), and
7. a rerun with the control enforced, showing the canary no longer leaves —
   observed prevention for this chain.

```bash
pip install -e ".[demo]"
python demo/flagship_demo.py
```

The run exits 0 only if Run 1 leaks and Run 2 does not, so it doubles as a smoke
test of the claim.

**What it proves.** The reference API *permits* the two-step sequence, and the
proposed control changes the observed outcome. The replay is deterministic
scripted execution — it is **not** evidence that a language model would
independently choose these steps, and it says nothing about any real third-party
API.

## Recording

`record.sh` runs the demo, or records it with asciinema (`cast`) and renders a
GIF (`gif`) for the README or a launch video. See the script header for prereqs.
