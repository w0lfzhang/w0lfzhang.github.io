#!/bin/bash
imgs=`./qrsctl listprefix wolfzhangspace  ''`
i=0
echo $imgs | tr " " "\n" | while read line
do
    if(($i>0))
    then
        echo $line
        ./qrsctl get wolfzhangspace $line ./$line
    fi
    i=$(($i+1))
done
