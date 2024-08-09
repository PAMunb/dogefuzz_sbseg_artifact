#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <contract_dir> <result_prefix>"
    exit 1
fi

contract_folder="$1"
result_prefix="$2"
pattern="subdir*"


for subdir in "$contract_folder"/$pattern/;  do
    if [ -d "$subdir" ]; then
	current_time=$(date +'%H%M%S')
	tmux new-session -d -s "${result_prefix}_${current_time}" ./benchmark.sh all "$subdir" 60m 'directed_greybox;blackbox;greybox;other_directed_greybox' 1 "$result_prefix"
	sleep 1
   fi
done
