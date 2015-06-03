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

package inet_dns_extension.networks.simple_mdns_example;

import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHost;
import inet_dns_extension.applications.mdns.MDNSNode;
import inet.networklayer.autorouting.ipv4.IPv4NetworkConfigurator;
import inet.nodes.ethernet.Eth1G;

network Simple_mdns_example
{
    @display("bgb=894,645");
    submodules:
        alice: MDNSNode {
            hname = "alice";
            sfile = "services/alice.ssh.service";
            @display("p=280,344;i=device/laptop");
        }
        bob: MDNSNode {
            hname = "bob";
            sfile = "services/bob.ssh.service";
            @display("p=432,344;i=device/laptop");
        }
        multicast_router: Router {
            forwardMulticast = true;
            @display("p=360,265");
            
            gates:
                pppg[3];
        }
        configurator: IPv4NetworkConfigurator {
            config = xmldoc("config.xml");
            @display("p=121,37");
        }
        carol: StandardHost {
            @display("p=538,244");
        }
    connections:
        alice.pppg++ <--> Eth1G <--> multicast_router.pppg[0];
        bob.pppg++ <--> Eth1G <--> multicast_router.pppg[1];
        carol.pppg++ <--> Eth1G <--> multicast_router.pppg[2];
}
