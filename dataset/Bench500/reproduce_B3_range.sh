#!/bin/bash

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <contract_dir> <result_prefix> <start_index> <end_index>"
    exit 1
fi

contract_folder="$1"
result_prefix="$2"
start_index="$3"
end_index="$4"

for ((i=start_index; i<=end_index; i++)); do
    pattern="subdir${i}"  # Adjust the pattern based on the current index
    for subdir in "$contract_folder"/$pattern/; do
        if [ -d "$subdir" ]; then
            current_time=$(date +'%H%M%S')
            tmux new-session -d -s "${result_prefix}_${current_time}" ./benchmark.sh all "$subdir" 1m 'directed_greybox' 1 "$result_prefix"
            sleep 1
        fi
    done
done
