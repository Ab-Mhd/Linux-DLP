#!/bin/bash

# Run the file tagging script and display the output
echo "Running file tagging script on /fanotify_dlp-main/test_data/sample.txt"
python3 fanotify_dlp-main/tags.py -d fanotify_dlp-main/test_data/ -x txt

if [ $? -eq 0 ]; then
    echo "File tagging completed successfully."
else
    echo "File tagging failed."
    exit 1
fi

# Start the clipboard monitor
echo "Starting clipboard monitor"
gnome-terminal -- bash -c "python3 linux-clipboard-monitor-main/main.py; exec bash"

if [ $? -eq 0 ]; then
    echo "Successfully started clipboard monitor."
else
    echo "Failed to start clipboard monitor."
    exit 1
fi

# Run the DLP build script
echo "Running DLP build script"
fanotify_dlp-main/build_main.sh

if [ $? -eq 0 ]; then
    echo "DLP build completed successfully."
else
    echo "DLP build failed."
    exit 1
fi

# Start the DLP process
echo "Starting DLP"
./fanotify_dlp-main/main.out fanotify_dlp-main/rule.json fanotify_dlp-main/test_data/sample.txt

if [ $? -eq 0 ]; then
    echo "DLP process started successfully."
else
    echo "Failed to start DLP process."
    exit 1
fi

