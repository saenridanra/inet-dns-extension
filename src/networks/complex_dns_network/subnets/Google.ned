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
import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHost;
import opp_dns_extension.applications.dns.DNSServerNode;

network Google
{
    @display("bgb=964,722");
    gates:
        inout ethg;
    submodules:
        ns1_google_com: DNSServerNode {
            auth.recursion_available = 0;
            auth.root_servers = "ComplexDNSNetwork.rootservers.i_root ComplexDNSNetwork.rootservers.b_root";
            m_file = "subnets/ns1.google.com.zone";
            @display("p=130,580");
        }
        ns2_google_com: DNSServerNode {
            auth.recursion_available = 0;
            auth.root_servers = "ComplexDNSNetwork.rootservers.i_root ComplexDNSNetwork.rootservers.b_root";
            m_file = "subnets/ns2.google.com.zone";
            @display("p=277,580");
        }
        ns3_google_com: DNSServerNode {
            auth.recursion_available = 0;
            auth.root_servers = "ComplexDNSNetwork.rootservers.i_root ComplexDNSNetwork.rootservers.b_root";
            m_file = "subnets/ns3.google.com.zone";
            @display("p=425,580");
        }
        ns4_google_com: DNSServerNode {
            auth.recursion_available = 0;
            auth.root_servers = "ComplexDNSNetwork.rootservers.i_root ComplexDNSNetwork.rootservers.b_root";
            m_file = "subnets/ns4.google.com.zone";
            @display("p=571,580");
        }
        google_ns1_subnet: Router {
            @display("p=130,499");
        }
        google_ns2_subnet: Router {
            @display("p=277,499");
        }
        google_ns3_subnet: Router {
            @display("p=425,499");
        }
        google_ns4_subnet: Router {
            @display("p=571,499");
        }
        google_front: Router {
            @display("p=571,379");
        }
        google_out: Router {
            @display("p=350,234");
        }
        server0_google_com: StandardHost {
            @display("p=798,156");
        }
        server1_google_com: StandardHost {
            @display("p=798,211");
        }
        server2_google_com: StandardHost {
            @display("p=798,269");
        }
        server3_google_com: StandardHost {
            @display("p=896,156");
        }
        server4_google_com: StandardHost {
            @display("p=896,211");
        }
        server5_google_com: StandardHost {
            @display("p=896,269");
        }
        server6_google_com: StandardHost {
            @display("p=712,350");
        }
        server7_google_com: StandardHost {
            @display("p=712,406");
        }
        server8_google_com: StandardHost {
            @display("p=712,470");
        }
        server9_google_com: StandardHost {
            @display("p=798,350");
        }
        server10_google_com: StandardHost {
            @display("p=798,406");
        }
        server11_google_com: StandardHost {
            @display("p=798,470");
        }
        server12_google_com: StandardHost {
            @display("p=896,350");
        }
        server13_google_com: StandardHost {
            @display("p=896,406");
        }
        server14_google_com: StandardHost {
            @display("p=896,470");
        }
        google_internal: Router {
            @display("p=350,333");
        }
    connections:
        ns1_google_com.ethg++ <--> Eth10G <--> google_ns1_subnet.ethg++;
        ns2_google_com.ethg++ <--> Eth10G <--> google_ns2_subnet.ethg++;
        ns3_google_com.ethg++ <--> Eth10G <--> google_ns3_subnet.ethg++;
        ns4_google_com.ethg++ <--> Eth10G <--> google_ns4_subnet.ethg++;
        server0_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server3_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server1_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server4_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server2_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server5_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server6_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server9_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server12_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server7_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server10_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server13_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server8_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server11_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        server14_google_com.ethg++ <--> Eth10G <--> google_front.ethg++;
        google_out.ethg++ <--> Eth100G <--> ethg;
        google_ns1_subnet.ethg++ <--> Eth10G <--> google_internal.ethg++;
        google_ns2_subnet.ethg++ <--> Eth10G <--> google_internal.ethg++;
        google_ns3_subnet.ethg++ <--> Eth10G <--> google_internal.ethg++;
        google_ns4_subnet.ethg++ <--> Eth10G <--> google_internal.ethg++;
        google_front.ethg++ <--> Eth10G <--> google_out.ethg++;
        google_internal.ethg++ <--> Eth10G <--> google_out.ethg++;
}
