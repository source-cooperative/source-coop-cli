#!/bin/bash
# cast.sh NAME...: record each tape as an asciicast against a fresh stub API.
D=/Users/alukach/.claude/jobs/7cb421d2/tmp/demo
mkdir -p $D/casts
for name in "$@"; do
  port=$(( $(grep -o '127.0.0.1:[0-9]*' $D/tapes/$name.tape | cut -d: -f2) + 100 ))
  python3 -I $D/stub_api.py $port & pid=$!
  sleep 0.5
  title="source-coop $(echo $name | sed 's/-i$/ -i/; s/-/ /')"
  script -q /dev/null asciinema rec -q --overwrite -i 2 --cols 130 --rows 30 -t "$title" \
    -c "python3 -I $D/drive.py $D/tapes/$name.tape $port" $D/casts/$name.cast >/dev/null 2>$D/casts/$name.err
  kill $pid; wait $pid 2>/dev/null
  echo "$name: $(wc -c < $D/casts/$name.cast) bytes, \"$title\""
done
