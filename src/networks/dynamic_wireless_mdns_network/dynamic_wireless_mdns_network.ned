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

package inet_dns_extension.networks.dynamic_wireless_mdns_network;

import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.node.wireless.AccessPoint;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet_dns_extension.applications.mdns.WirelessMDNSNode;
import inet.networklayer.configurator.ipv4.IPv4NetworkConfigurator;
import inet.node.ethernet.Eth1G;
import inet_dns_extension.common.generation.MDNSNetworkConfigurator;

network Dynamic_wireless_mdns_network
{
    parameters:
        int p_num_resolvers;
        int p_num_private;
        int p_max_friends;
        int p_min_friends;
        int p_max_services = default(10);
        int p_min_services = default(10);

        double p_private_service_ratio = default(100.0);

        @display("bgb=1046,645");

    submodules:
        mdns_host[p_num_resolvers]: WirelessMDNSNode;
        multicast_router: Router {
            multicastForwarding = true;
            numRadios = 1;
            @display("p=394,314");
        }

        ap: AccessPoint {
            @display("p=517,303");
        }

        radioMedium: Ieee80211ScalarRadioMedium {
            parameters:
                @display("p=100,50");
        }

        configurator: IPv4NetworkConfigurator {
            config = xmldoc("config.xml");
            @display("p=121,37");
        }

        mdns_configurator: MDNSNetworkConfigurator {
            num_resolvers = p_num_resolvers;
            num_private = p_num_private;
            max_friends = p_max_friends;
            min_friends = p_min_friends;
            max_services = p_max_services;
            min_services = p_min_services;

            private_service_ratio = p_private_service_ratio;

        }
     //connections:
     //    ap.ethg++ <--> Eth1G <--> multicast_router.ethg++;


}
