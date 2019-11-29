#!/bin/bash


help() {
    echo "Usage: $0 [-s]"
    echo "-s    fuzz simple linter with own strcmp"
    exit 1;
}


binpath='./simple_linter-afl'
while getopts shl OPT; do
    case $OPT in
        "s" ) binpath='./simple_linter_strcmp-afl';;
        "l" ) binpath='./simple_linter_laf-intel';;
        "h" ) help;;
    esac
done


afl_cmd="$LD_PRELOAD_OPT afl-fuzz -i in_dir -o out_dir -f input -- $binpath input"
echo $afl_cmd
eval $afl_cmd
