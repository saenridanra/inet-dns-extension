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
        imap: StandardHost {
            @display("p=95,530;i=device/mainframe");
        }
        proxy_neu_rz: StandardHost {
            @display("p=112,597;i=device/mainframe");
        }
        cms: StandardHost {
            @display("p=195,597;i=device/mainframe");
        }
        rz: Router {
            @display("p=176,530");
        }
        uni_konstanz: StandardHost {
            @display("p=134,468;i=device/mainframe");
        }
        rz_dns: Router {
            @display("p=569,550");
        }
        pan_rz: DNSServerNode {
            auth.root_servers = "Stateless_example_network.rootservers.i_root Stateless_example_network.rootservers.b_root";
            m_file = "subnets/pan.rz.uni-konstanz.de.zone";
            @display("p=569,634;i=device/server");
        }
        uranos_rz: DNSServerNode {
            auth.root_servers = "Stateless_example_network.rootservers.i_root Stateless_example_network.rootservers.b_root";
            m_file = "subnets/uranos.rz.uni-konstanz.de.zone";
            @display("p=508,550;i=device/server");
        }
        local_cache: DNSCachingServerNode {
            lc.root_servers = "Stateless_example_network.rootservers.i_root Stateless_example_network.rootservers.b_root";
            @display("p=653,550;i=device/server2");
        }
        uni_out: Router {
            @display("p=581,261;i=abstract/router2");
        }
        uni_internal: Router {
            @display("p=840,261");
        }
        uni_internal_2: Router {
            @display("p=840,122");
        }
        htwg_dns: Router {
            @display("p=856,529");
        }
        dns3: DNSServerNode {
            auth.root_servers = "Stateless_example_network.rootservers.i_root Stateless_example_network.rootservers.b_root";
            m_file = "subnets/dns3.uni-konstanz.de.zone";
            @display("p=921,597;i=device/server");
        }
        netfuture_dns: Router {
            @display("p=239,263");
        }
        echo: DNSEchoServerNode {
            ns = "eho.netfuture.ch";
            ns_ip = "87.245.127.186";
            @display("p=100,263;i=device/server");
        }
        uni_bgp_out: Router {
            @display("p=581,161;i=abstract/switch");
        }
        client1: DNSClientNode {
            @display("p=953,214;i=device/laptop");
        }
        client2: DNSClientNode {
            @display("p=953,263;i=device/laptop");
        }
        client3: DNSClientNode {
            @display("p=953,313;i=device/laptop");
        }
        client4: DNSClientNode {
            @display("p=887,39;i=device/laptop");
        }
        client5: DNSClientNode {
            @display("p=952,58;i=device/laptop");
        }
        client6: DNSClientNode {
            @display("p=973,109;i=device/laptop");
        }
    connections:
        imap.ethg++ <--> Eth1G <--> rz.ethg++;
        proxy_neu_rz.ethg++ <--> Eth1G <--> rz.ethg++;
        cms.ethg++ <--> Eth1G <--> rz.ethg++;
        uni_konstanz.ethg++ <--> Eth1G <--> rz.ethg++;
        uranos_rz.ethg++ <--> Eth1G <--> rz_dns.ethg++;
        pan_rz.ethg++ <--> Eth1G <--> rz_dns.ethg++;
        local_cache.ethg++ <--> Eth1G <--> rz_dns.ethg++;
        dns3.ethg++ <--> Eth1G <--> htwg_dns.ethg++;
        echo.ethg++ <--> Eth1G <--> netfuture_dns.ethg++;
        rz.ethg++ <--> Eth10G <--> uni_out.ethg++;
        rz_dns.ethg++ <--> Eth10G <--> uni_out.ethg++;
        htwg_dns.ethg++ <--> Eth10G <--> uni_out.ethg++;
        netfuture_dns.ethg++ <--> Eth10G <--> uni_out.ethg++;
        uni_out.ethg++ <--> Eth10G <--> uni_bgp_out.ethg++;
        uni_bgp_out.ethg++ <--> Eth100G <--> ethg;
        uni_internal.ethg++ <--> Eth1G <--> uni_out.ethg++;
        uni_internal_2.ethg++ <--> Eth1G <--> uni_out.ethg++;
        client1.ethg++ <--> Eth1G <--> uni_internal.ethg++;
        client2.ethg++ <--> Eth1G <--> uni_internal.ethg++;
        client3.ethg++ <--> Eth1G <--> uni_internal.ethg++;
        client4.ethg++ <--> Eth1G <--> uni_internal_2.ethg++;
        client5.ethg++ <--> Eth1G <--> uni_internal_2.ethg++;
        client6.ethg++ <--> Eth1G <--> uni_internal_2.ethg++;
}
