#!/bin/bash
# render.sh NAME...: render each tape against a fresh stub API on its port.
D=/Users/alukach/.claude/jobs/7cb421d2/tmp/demo
for name in "$@"; do
  port=$(grep -o '127.0.0.1:[0-9]*' $D/tapes/$name.tape | cut -d: -f2)
  python3 -I $D/stub_api.py $port & pid=$!
  sleep 0.5
  vhs $D/tapes/$name.tape >/dev/null 2>$D/out/$name.log || echo "$name: vhs failed"
  kill $pid; wait $pid 2>/dev/null
  echo "$name: $(ls -la $D/out/$name.gif 2>/dev/null | awk '{print $5}') bytes"
done
