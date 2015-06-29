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

package inet_dns_extension.networks.stateless_network.subnets;

import inet.node.ethernet.Eth100G;
import inet.node.ethernet.Eth10G;
import inet.node.inet.Router;
import inet_dns_extension.applications.dns.DNSServerNode;


module CH
{
    @display("bgb=761,521");
    gates:
        inout ethg;
    submodules:
        a_nic_ch: DNSServerNode {
            auth.recursion_available = 0;
            auth.root_servers = "Stateless_example_network.rootservers.i_root Stateless_example_network.rootservers.b_root";
            m_file = "subnets/a.nic.ch.zone";
            @display("p=365,320");
        }
        ch_bgp_out: Router {
            @display("p=365,179");
        }
        ch_out: Router {
            @display("p=365,254");
        }
    connections:
        a_nic_ch.ethg++ <--> Eth10G <--> ch_out.ethg++;
        ch_out.ethg++ <--> Eth10G <--> ch_bgp_out.ethg++;
        ch_bgp_out.ethg++ <--> Eth100G <--> ethg;
}
