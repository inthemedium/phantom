#!/bin/bash

branch_name="$(git symbolic-ref HEAD 2>/dev/null)" ||
branch_name="(unnamed branch)"     # detached HEAD
branch_name=${branch_name##refs/heads/}

git diff | ssh $1 "cd phantom && git checkout -f && git pull && git checkout $branch_name && git apply && cd protos && ./generate_protos.sh && cd ../src && make clean && make"
