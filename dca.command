#!/bin/bash
# Double-click this file in Finder to start DigitalCertiAnalytics on macOS.
# It shows the options, asks which ones to run and keeps the window open at the end.
# In a terminal you can use the dca launcher directly, e.g.:  ./dca --leaf_analysis

# Exit code of the program when it did not understand the options (argparse)
USAGE_ERROR=2

cd "$(dirname "$0")" || exit 1
/bin/sh ./dca --help
status=$?
if [ "$status" -eq 0 ]; then
    echo
    echo "Type the options to run, for example:  --leaf_analysis --plot_leaf_results"
    echo "To save disk space, --compress_input makes res/certs_polito.json about 5 times smaller."
    while :; do
        printf 'Options (or just press Enter to close): '
        read -r options || exit 0
        [ -n "$options" ] || exit 0
        set -f  # The options are split into words, but '*' and '?' are not expanded
        # shellcheck disable=SC2086
        /bin/sh ./dca $options
        status=$?
        set +f
        [ "$status" -eq "$USAGE_ERROR" ] || break
        # Nothing was run: ask again instead of closing the window
        echo
        echo "Those options were not understood. Every option starts with two dashes, for example:  --leaf_analysis"
        echo "The list of the options is above."
    done
fi
echo
printf 'Press Enter to close this window...'
read -r _
exit "$status"
