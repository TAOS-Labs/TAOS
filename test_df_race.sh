#!/bin/bash

# Total count of "DOUBLE FAULT" occurrences
double_fault_count=0
runs=1
timeout_duration=17s  # Adjust this duration as needed

for i in $(seq 1 $runs); do
    echo "Run $i/$runs..."
    # Run the command, but kill it after timeout_duration seconds.
    # This forces QEMU to exit if it hasn't already.
    output=$(timeout $timeout_duration make run-term 2>&1)

    echo "$output" &> "dump.txt"
    # # Count occurrences of "DOUBLE FAULT" in the output
    # count=$(echo "$output")
    # echo "Found $count occurrences in run $i."
    
done
