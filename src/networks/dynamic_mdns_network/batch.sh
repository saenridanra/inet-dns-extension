#!/bin/sh

# This batch script runs a specific configuration with all possible run params.
PROJECT_PATH=$1
INET_PATH=$2
CONFIG=$3
RUN_LOW=$4
RUN_HIGH=$5

for i in `seq $4 $5`
do
    opp_run -l $PROJECT_PATH/src/opp_dns_extension -l $PROJECT_PATH/lib/inet -n "$PROJECT_PATH/src;$INET_PATH/src" $PROJECT_PATH/src/networks/dynamic_mdns_network/omnetpp.ini -u Cmdenv -c $3 -r $i
done
