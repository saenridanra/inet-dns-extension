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

package opp_dns_extension.networks.complex_dns_network.subnets;

import inet.examples.inet.ipv4largenet.cable;
import inet.nodes.ethernet.Eth100G;
import inet.nodes.ethernet.EtherLink;
import inet.nodes.inet.Router;
import opp_dns_extension.applications.DNSServerNode;

network RootServers
{
    gates:
        inout ethg;
    submodules:
        i_root: DNSServerNode {
            parameters:
                auth.recursion_available = 0;
                m_file = "subnets/i.root-servers.net.zone";
                @display("p=451,249");
        }
        b_root: DNSServerNode {
            parameters:
                m_file = "subnets/b.root-servers.net.zone";
                @display("p=570,249");
        }
        root_server_bgp: Router {
            @display("p=509,464");
        }
        i_root_router: Router {
            @display("p=451,347");
        }
        b_root_router: Router {
            @display("p=570,347");
        }
    connections:
        i_root.ethg++ <--> Eth100G <--> i_root_router.ethg++;
        b_root.ethg++ <--> Eth100G <--> b_root_router.ethg++;
        i_root_router.ethg++ <--> Eth100G <--> root_server_bgp.ethg++;
        b_root_router.ethg++ <--> Eth100G <--> root_server_bgp.ethg++;
        root_server_bgp.ethg++ <--> Eth100G <--> ethg;
}
