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

package inet_dns_extension.networks.complex_dns_network;

import inet.examples.inet.ipv4largenet.IPv4LargeLAN;
import inet.node.bgp.BGPRouter;
import inet.node.ethernet.Eth100G;
import inet_dns_extension.networks.complex_dns_network.subnets.COM;
import inet_dns_extension.networks.complex_dns_network.subnets.DE;
import inet_dns_extension.networks.complex_dns_network.subnets.Google;
import inet_dns_extension.networks.complex_dns_network.subnets.RootServers;
import inet_dns_extension.networks.complex_dns_network.subnets.UniKonstanz;
import inet.networklayer.configurator.ipv4.IPv4NetworkConfigurator;
import inet.node.inet.Router;


network ComplexDNSNetwork
{
    @display("bgb=1071,606");
    submodules:
        interconnect: Router {
            @display("p=508,318");
        }
        com: COM {
            @display("p=393,230");
        }
        de: DE {
            @display("p=393,389");
        }
        rootservers: RootServers {
            @display("p=651,318");
        }
        unikonstanz: UniKonstanz {
            @display("p=651,164");
        }
        google: Google {
            @display("p=508,164");
        }
        configurator: IPv4NetworkConfigurator {
            config = xmldoc("network_config.xml");
            @display("p=121,37");
        }
    connections:
        com.ethg <--> interconnect.ethg++;
        de.ethg <--> interconnect.ethg++;
        rootservers.ethg <--> interconnect.ethg++;
        unikonstanz.ethg <--> interconnect.ethg++;
        google.ethg <--> interconnect.ethg++;
}
