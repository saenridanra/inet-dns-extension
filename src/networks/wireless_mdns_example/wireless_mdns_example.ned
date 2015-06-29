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

import inet.node.inet.Router;
import inet.node.wireless.AccessPoint;
import inet_dns_extension.applications.mdns.WirelessMDNSNode;
import inet.networklayer.configurator.ipv4.IPv4NetworkConfigurator;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.node.ethernet.Eth1G;

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
            multicastForwarding = true;
            @display("p=357,194");
        }
        ap: AccessPoint {
            @display("p=349,271");
        }
        radioMedium: Ieee80211ScalarRadioMedium {
            parameters:
                @display("p=100,50");
        }
        configurator: IPv4NetworkConfigurator {
            config = xmldoc("config.xml");
            @display("p=121,37");
        }
    connections:
}
