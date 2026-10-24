#!/bin/bash
# Double-click this file in Finder to install DigitalCertiAnalytics on macOS.
# It runs install.sh in a Terminal window and keeps the window open at the end, so you can read the result.
# If macOS says it "could not verify" the file: open System Settings > Privacy & Security and click "Open Anyway",
# or paste this in Terminal instead:  curl -fsSL https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.sh | bash

cd "$(dirname "$0")" || exit 1
/bin/sh ./install.sh "$@"
status=$?
echo
if [ "$status" -eq 0 ]; then
    echo "Done. You can close this window."
else
    echo "The installation did not finish: read the messages above to see what to do, then run it again."
fi
printf 'Press Enter to close this window...'
read -r _
exit "$status"
