#!/usr/bin/env bash

ghc main.hs DES.hs

tmpfile=$(mktemp)
outfile=$(mktemp)

exp=1
for (( i=0; i < 22; i++ ))
do
    head -c $exp /dev/urandom > "$tmpfile"
    /usr/bin/time -a -o running_times.test -f %E ./main -p password encrypt $tmpfile $outfile
    echo Finished size $exp
    exp=$((exp*2 ))
done

