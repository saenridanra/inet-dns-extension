#!/bin/bash
cd /home/saen/Disy/sources/opp_dns_extension/src/networks/stateless_network
opp_run -l /home/saen/Disy/sources/opp_dns_extension/src/opp_dns_extension -l /home/saen/Disy/sources/opp_dns_extension/lib/inet -n "/home/saen/Disy/sources/opp_dns_extension/src;/LinuxFiles/Workspaces/opp_workspace/inet/src" /home/saen/Disy/sources/opp_dns_extension/src/networks/stateless_network/omnetpp.ini
