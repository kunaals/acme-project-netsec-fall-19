#!/bin/bash

NUM=$1

echo "Running acme_client.py $NUM times"

for i in $(seq 1 $NUM);
do 
   ( /usr/local/opt/python/bin/python3.7 /Users/kunaalsikka/Code/ksikka-acme-project-netsec-fall-19/project/acme_client.py & )
   echo "Running"
done
