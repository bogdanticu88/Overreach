# Security policy

## Reporting a vulnerability in this tool

Email the maintainer privately. Do not open a public issue for a security
report. You will get an acknowledgement within a few days.

## How this tool treats its inputs

Every spec, boundaries file and model response is treated as hostile.

- Nothing from an input is executed, imported, or passed to a shell.
- YAML is parsed in safe mode only.
- External `$ref` targets are never fetched. Internal refs are depth-limited.
- Spec size, nesting depth and reference count are bounded.
- Model output is schema-validated and never outranks a deterministic rule.
- Replay (reference API only, in later versions) runs in a container with no
  outbound network and a time limit.
- Model API keys are read from the environment and redacted from all output.

## Rules of engagement for the scanner's replay

The open-source replay targets only the bundled reference API or a local URL
you pass explicitly. Do not point replay at a system you are not authorised to
test. Any real vulnerability found in third-party software during research is
reported privately to that project through its own security policy, and nothing
is published until the project has had time to respond.
