#!/bin/bash
cd /home/saen/master-project/sources/opp_dns_extension/src/networks/simple_mdns_privacy_example
opp_run -l /home/saen/master-project/sources/opp_dns_extension/src/opp_dns_extension -l /home/saen/master-project/sources/opp_dns_extension/lib/inet -n "/home/saen/master-project/sources/opp_dns_extension/src;/home/saen/master-project/workspaces/omnetpp/inet/src" /home/saen/master-project/sources/opp_dns_extension/src/networks/simple_mdns_privacy_example/omnetpp.ini
