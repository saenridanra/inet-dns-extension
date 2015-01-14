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

import inet.nodes.ethernet.Eth100G;
import inet.nodes.ethernet.Eth10G;
import inet.nodes.ethernet.Eth1G;
import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHost;
import opp_dns_extension.applications.dns.DNSClientNode;
import opp_dns_extension.applications.dns.DNSServerNode;


network UniKonstanz
{
    @display("bgb=1013,696");
    gates:
        inout ethg;
    submodules:
        imap: StandardHost {
            @display("p=76,463");
        }
        proxy_neu_rz: StandardHost {
            @display("p=188,463");
        }
        cms: StandardHost {
            @display("p=291,463");
        }
        rz: Router {
            @display("p=246,381");
        }
        uni_konstanz: StandardHost {
            @display("p=401,463");
        }
        rz_dns: Router {
            @display("p=581,375");
        }
        pan_rz: DNSServerNode {
            auth.root_servers = "ComplexDNSNetwork.rootservers.i_root ComplexDNSNetwork.rootservers.b_root";
            m_file = "subnets/pan.rz.uni-konstanz.de.zone";
            @display("p=616,463");
        }
        uranos_rz: DNSServerNode {
            auth.root_servers = "ComplexDNSNetwork.rootservers.i_root ComplexDNSNetwork.rootservers.b_root";
            m_file = "subnets/uranos.rz.uni-konstanz.de.zone";
            @display("p=542,463");
        }
        uni_out: Router {
            @display("p=581,261");
        }
        uni_internal: Router {
            @display("p=762,261");
        }
        htwg_dns: Router {
            @display("p=762,375");
        }
        dns3: DNSServerNode {
            auth.root_servers = "ComplexDNSNetwork.rootservers.i_root ComplexDNSNetwork.rootservers.b_root";
            m_file = "subnets/dns3.uni-konstanz.de.zone";
            @display("p=762,463");
        }
        uni_bgp_out: Router {
            @display("p=581,161");
        }
        uni_dns_client: DNSClientNode {
            @display("p=913,261");
        }
    connections:
        imap.ethg++ <--> Eth1G <--> rz.ethg++;
        proxy_neu_rz.ethg++ <--> Eth1G <--> rz.ethg++;
        cms.ethg++ <--> Eth1G <--> rz.ethg++;
        uni_konstanz.ethg++ <--> Eth1G <--> rz.ethg++;
        uranos_rz.ethg++ <--> Eth1G <--> rz_dns.ethg++;
        pan_rz.ethg++ <--> Eth1G <--> rz_dns.ethg++;
        dns3.ethg++ <--> Eth1G <--> htwg_dns.ethg++;
        rz.ethg++ <--> Eth10G <--> uni_out.ethg++;
        rz_dns.ethg++ <--> Eth10G <--> uni_out.ethg++;
        htwg_dns.ethg++ <--> Eth10G <--> uni_out.ethg++;
        uni_out.ethg++ <--> Eth10G <--> uni_bgp_out.ethg++;
        uni_bgp_out.ethg++ <--> Eth100G <--> ethg;
        uni_internal.ethg++ <--> Eth1G <--> uni_out.ethg++;
        uni_dns_client.ethg++ <--> Eth1G <--> uni_internal.ethg++;
}
