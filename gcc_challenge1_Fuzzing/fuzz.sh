#!/bin/bash


help() {
    echo "Usage: $0 [-s]"
    echo "-s    use custom built strcmp.so"
    exit 1;
}


LD_PRELOAD_OPT=""
while getopts sh OPT; do
    case $OPT in
        "s" ) LD_PRELOAD_OPT="LD_PRELOAD=./strcmp/strcmp.so";;
        "h" ) help;;
    esac
done


afl_cmd="$LD_PRELOAD_OPT afl-fuzz -i in_dir -o out_dir -f input -- ./simple_linter-afl input"
echo $afl_cmd
eval $afl_cmd
