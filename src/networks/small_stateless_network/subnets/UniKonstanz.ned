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

package inet_dns_extension.networks.small_stateless_network.subnets;

import inet.node.ethernet.Eth100G;
import inet.node.ethernet.Eth10G;
import inet.node.ethernet.Eth1G;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet_dns_extension.applications.dns.DNSClientNode;
import inet_dns_extension.applications.dns.DNSServerNode;
import inet_dns_extension.applications.dns.DNSEchoServerNode;
import inet_dns_extension.applications.dns.DNSCachingServerNode;


network UniKonstanz
{
    @display("bgb=1013,696");
    gates:
        inout ethg;
    submodules:
        rz_dns: Router {
            @display("p=569,424");
        }
        pan_rz: DNSServerNode {
            auth.root_servers = "Small_stateless_example_network.rootservers.i_root Small_stateless_example_network.rootservers.b_root";
            m_file = "subnets/pan.rz.uni-konstanz.de.zone";
            @display("p=569,508;i=device/server");
        }
        uranos_rz: DNSServerNode {
            auth.root_servers = "Small_stateless_example_network.rootservers.i_root Small_stateless_example_network.rootservers.b_root";
            m_file = "subnets/uranos.rz.uni-konstanz.de.zone";
            @display("p=508,424;i=device/server");
        }
        local_cache: DNSCachingServerNode {
            lc.root_servers = "Small_stateless_example_network.rootservers.i_root Small_stateless_example_network.rootservers.b_root";
            @display("p=653,424;i=device/server2");
        }
        uni_out: Router {
            @display("p=569,261;i=abstract/router2");
        }
        uni_internal: Router {
            @display("p=779,309");
        }
        uni_internal_2: Router {
            @display("p=779,192");
        }
        netfuture_dns: Router {
            @display("p=415,261");
        }
        echo: DNSEchoServerNode {
            ns = "eho.netfuture.ch";
            ns_ip = "87.245.127.186";
            @display("p=267,261;i=device/server");
        }
        uni_bgp_out: Router {
            @display("p=569,157;i=abstract/switch");
        }
        client1: DNSClientNode {
            @display("p=899,309;i=device/laptop");
        }
        client2: DNSClientNode {
            @display("p=899,192;i=device/laptop");
        }
    connections:
        uranos_rz.ethg++ <--> Eth1G <--> rz_dns.ethg++;
        pan_rz.ethg++ <--> Eth1G <--> rz_dns.ethg++;
        local_cache.ethg++ <--> Eth1G <--> rz_dns.ethg++;
        echo.ethg++ <--> Eth1G <--> netfuture_dns.ethg++;
        rz_dns.ethg++ <--> Eth10G <--> uni_out.ethg++;
        netfuture_dns.ethg++ <--> Eth10G <--> uni_out.ethg++;
        uni_out.ethg++ <--> Eth10G <--> uni_bgp_out.ethg++;
        uni_bgp_out.ethg++ <--> Eth100G <--> ethg;
        uni_internal.ethg++ <--> Eth1G <--> uni_out.ethg++;
        uni_internal_2.ethg++ <--> Eth1G <--> uni_out.ethg++;
        client1.ethg++ <--> Eth1G <--> uni_internal.ethg++;
        client2.ethg++ <--> Eth1G <--> uni_internal_2.ethg++;
}
