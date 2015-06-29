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

package inet_dns_extension.networks.complex_dns_network.subnets;

import inet.node.ethernet.Eth100G;
import inet.node.ethernet.Eth10G;
import inet.node.inet.Router;
import inet_dns_extension.applications.dns.DNSServerNode;

module COM
{
    gates:
        inout ethg;
    submodules:
        a_gtld_servers_net: DNSServerNode {
            auth.recursion_available = 0;
            auth.root_servers = "ComplexDNSNetwork.rootservers.i_root ComplexDNSNetwork.rootservers.b_root";
            m_file = "subnets/a.gtld-servers.net.zone";
            @display("p=365,337");
        }
        com_bgp_out: Router {
            @display("p=365,179");
        }
        com_out: Router {
            @display("p=365,254");
        }
    connections:
        a_gtld_servers_net.ethg++ <--> Eth10G <--> com_out.ethg++;
        com_out.ethg++ <--> Eth10G <--> com_bgp_out.ethg++;
        com_bgp_out.ethg++ <--> Eth100G <--> ethg;
}
