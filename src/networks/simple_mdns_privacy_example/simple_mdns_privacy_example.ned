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

package opp_dns_extension.networks.simple_mdns_privacy_example;

import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHost;
import opp_dns_extension.applications.mdns.MDNSNode;
import inet.networklayer.autorouting.ipv4.IPv4NetworkConfigurator;
import inet.nodes.ethernet.Eth1G;
import opp_dns_extension.common.generation.MDNSNetworkConfigurator;

network Simple_mdns_privacy_example
{
    @display("bgb=1046,645");
    types:
        simple Unnamed
        {
        }

    submodules:
        alice: MDNSNode {
            private = true;
            hname = "alice";
            sfile = "services/alice.ssh.service services/alice.presence.service  services/alice.privacy.service";
            privacy_sfile = "privacy_services/alice.ssh.service privacy_services/alice.presence.service";
            pdata = "bob,bob._privacy._tcp.local,dummykey;carol,carol._privacy._tcp.local,dummykey";
            own_instance = "alice";
            @display("p=287,499;i=device/laptop");
        }
        bob: MDNSNode {
            private = true;
            hname = "bob";
            sfile = "services/bob.ssh.service services/bob.presence.service  services/bob.privacy.service";
            privacy_sfile = "privacy_services/bob.ssh.service privacy_services/bob.presence.service";
            pdata = "alice,alice._privacy._tcp.local,dummykey;carol,carol._privacy._tcp.local,dummykey";
            own_instance = "bob";
            @display("p=509,499;i=device/laptop");
        }
        carol: MDNSNode {
            private = true;
            hname = "carol";
            sfile = "services/carol.ssh.service services/carol.presence.service  services/carol.privacy.service";
            privacy_sfile = "privacy_services/carol.presence.service";
            pdata = "alice,alice._privacy._tcp.local,dummykey;bob,bob._privacy._tcp.local,dummykey;dave,dave._privacy._tcp.local,dummykey";
            own_instance = "carol";
            @display("p=607,217;i=device/laptop");
        }
        dave: MDNSNode {
            private = true;
            hname = "dave";
            sfile = "services/dave.ssh.service services/dave.presence.service  services/dave.privacy.service";
            privacy_sfile = "privacy_services/dave.presence.service";
            pdata = "carol,carol._privacy._tcp.local,dummykey";
            own_instance = "dave";
            @display("p=399,112;i=device/laptop");
        }
        eve: StandardHost {
            @display("p=198,217;i=,#FF2121,30");
        }

        multicast_router: Router {
            forwardMulticast = true;
            @display("p=399,316");

            gates:
                pppg[5];
        }
        configurator: IPv4NetworkConfigurator {
            config = xmldoc("config.xml");
            @display("p=121,37");
        }
        
        mdns_configurator : MDNSNetworkConfigurator{
            num_resolvers = 4;
            num_private = 4;
            max_friends = 2;
            min_friends = 1;
            max_services = 10;
            min_services = 2;
            
            private_service_ratio = 100.0;
            
        }
        
        Start: StandardHost {
            @display("p=948,54;i=device/laptop,#080808;b=200,60,rect");
        }
        Hostname_Announced: StandardHost {
            @display("p=948,135;i=device/laptop,orange;b=200,60,rect");
        }
        Finished_Announce: StandardHost {
            @display("p=948,226;i=device/laptop,#449544,100;b=200,60,rect");
        }
        Multicast_Packet: StandardHost {
            @display("p=948,316;i=msg/bcast,red;b=200,60,rect");
        }
        Private_Unicast: StandardHost {
            @display("p=948,404;i=msg/packet,green;b=200,60,rect");
        }
    connections:
        alice.pppg++ <--> Eth1G <--> multicast_router.pppg[0];
        bob.pppg++ <--> Eth1G <--> multicast_router.pppg[1];
        carol.pppg++ <--> Eth1G <--> multicast_router.pppg[2];
        dave.pppg++ <--> Eth1G <--> multicast_router.pppg[3];
        eve.pppg++ <--> Eth1G <--> multicast_router.pppg[4];
}
