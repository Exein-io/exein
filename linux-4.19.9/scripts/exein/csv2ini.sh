#!/bin/bash
[ "$#" -ne 1 ] && echo "$0 hooks.csv" && exit 1;
IFS=$'\n';
for i in $(cat $1); do
    type=$(echo $i | cut -d, -f1);
    name=$(echo $i | cut -d, -f2);
    echo "[$name]";
    echo "type=\"$type\"";
    count=1;
    tmp=$(echo $i | cut -d, -f3-);
    IFS=$',';
    for j in $tmp; do
          echo "arg${count}=\"${j}\"";
          count=$((count+1));
          done;
    echo;
    IFS=$'\n';
    done
