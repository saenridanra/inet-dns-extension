//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package opp_dns_extension.networks.dynamic_mdns_network;

import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHost;
import opp_dns_extension.applications.mdns.MDNSNode;
import inet.networklayer.autorouting.ipv4.IPv4NetworkConfigurator;
import inet.nodes.ethernet.Eth1G;
import opp_dns_extension.common.generation.MDNSNetworkConfigurator;

network Dynamic_mdns_network
{
    parameters: 
        int p_num_resolvers;
        int p_num_private;
        int p_max_friends;
        int p_min_friends;
        int p_max_services = default(5);
        int p_min_services = default(5);
        
        double p_private_service_ratio = default(100.0);
    
    @display("bgb=1046,645");
    types:
        simple Unnamed
        {
        }

    submodules:
        mdns_host[p_num_resolvers]: MDNSNode {
        }

        multicast_router: Router {
            forwardMulticast = true;
            @display("p=399,316");

            gates:
                pppg[p_num_resolvers];
        }
        configurator: IPv4NetworkConfigurator {
            config = xmldoc("config.xml");
            @display("p=121,37");
        }
        
        mdns_configurator : MDNSNetworkConfigurator{
            num_resolvers = p_num_resolvers;
            num_private = p_num_private;
            max_friends = p_max_friends;
            min_friends = p_min_friends;
            max_services = p_max_services;
            min_services = p_min_services;
            
            private_service_ratio = p_private_service_ratio;
            
        }
        
    connections:
        for i=0..p_num_resolvers-1 {
            mdns_host[i].pppg++ <--> Eth1G <--> multicast_router.pppg[i];
        }
}
