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

package inet_dns_extension.networks.wireless_mdns_example;

import inet.nodes.inet.Router;
import inet.nodes.wireless.AccessPoint;
import inet_dns_extension.applications.mdns.WirelessMDNSNode;
import inet.networklayer.autorouting.ipv4.IPv4NetworkConfigurator;
import inet.world.radio.ChannelControl;
import inet.nodes.ethernet.Eth1G;

network Wireless_mdns_example
{
    @display("bgb=894,645");
    submodules:
        alice: WirelessMDNSNode {
            hname = "alice";
            sfile = "services/alice.ssh.service";
            @display("p=280,344;i=device/laptop");
        }
        bob: WirelessMDNSNode {
            hname = "bob";
            sfile = "services/bob.ssh.service";
            @display("p=432,344;i=device/laptop");
        }
        multicast_router: Router {
            forwardMulticast = true;
            @display("p=357,194");
        }
        ap: AccessPoint {
            @display("p=349,271");
        }
        channelControl: ChannelControl {
            @display("p=60,50");
        }
        configurator: IPv4NetworkConfigurator {
            config = xmldoc("config.xml");
            @display("p=121,37");
        }
    connections:
}
