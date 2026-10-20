#!/usr/bin/env bash
# Record the flagship Overreach demo as a terminal cast / GIF for the README or
# a launch video. Offline and deterministic: safe to record anywhere.
#
# Prereqs:
#   pip install -e ".[demo]"
#   asciinema  (optional, for the .cast) and agg (optional, for the .gif)
#
# Usage:
#   demo/record.sh            # just run the demo in the terminal
#   demo/record.sh cast       # record demo/overreach-demo.cast with asciinema
#   demo/record.sh gif        # record a cast, then render demo/overreach-demo.gif
set -euo pipefail
cd "$(dirname "$0")/.."

run() { python demo/flagship_demo.py 2>/dev/null; }

case "${1:-run}" in
  run)
    run
    ;;
  cast)
    command -v asciinema >/dev/null || { echo "asciinema not installed"; exit 1; }
    asciinema rec --overwrite --command "python demo/flagship_demo.py 2>/dev/null" \
      demo/overreach-demo.cast
    echo "wrote demo/overreach-demo.cast"
    ;;
  gif)
    command -v asciinema >/dev/null || { echo "asciinema not installed"; exit 1; }
    command -v agg >/dev/null || { echo "agg not installed (cargo install agg)"; exit 1; }
    asciinema rec --overwrite --command "python demo/flagship_demo.py 2>/dev/null" \
      demo/overreach-demo.cast
    agg demo/overreach-demo.cast demo/overreach-demo.gif
    echo "wrote demo/overreach-demo.gif"
    ;;
  *)
    echo "usage: demo/record.sh [run|cast|gif]"; exit 2;;
esac
