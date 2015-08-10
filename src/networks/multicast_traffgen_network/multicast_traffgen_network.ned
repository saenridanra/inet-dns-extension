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

package inet_dns_extension.networks.multicast_traffgen_network;

import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet_dns_extension.applications.traffic.MulticastTraffGen;
import inet.networklayer.configurator.ipv4.IPv4NetworkConfigurator;
import inet.node.ethernet.Eth1G;

network Multicast_traffgen_network
{
    @display("bgb=894,645");
    submodules:
        alice: MCastTraffGenNode {
            @display("p=280,344;i=device/laptop");
        }
        bob: MCastTraffGenNode {
            @display("p=432,344;i=device/laptop");
        }
        carol: MCastTraffGenNode {
            @display("p=538,244");
        }
        multicast_router: Router {
            multicastForwarding = true;
            @display("p=360,265");
            
            gates:
                pppg[3];
        }
        configurator: IPv4NetworkConfigurator {
            config = xmldoc("config.xml");
            @display("p=121,37");
        }
    connections:
        alice.pppg++ <--> Eth1G <--> multicast_router.pppg[0];
        bob.pppg++ <--> Eth1G <--> multicast_router.pppg[1];
        carol.pppg++ <--> Eth1G <--> multicast_router.pppg[2];
}

module MCastTraffGenNode extends StandardHost{
    parameters:
        hasUdp = true;
    	@display("p=432,344;i=device/laptop");
    	
    submodules:
        mtg: MulticastTraffGen {
        }
        
    connections:
		mtg.udpAppOut --> udp.appIn++;
		mtg.udpAppIn <-- udp.appOut++;
}