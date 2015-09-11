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

package inet_dns_extension.networks.dynamic_wireless_mtg_network;

import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.node.wireless.AccessPoint;
import inet.node.inet.WirelessHost;
import inet.node.ethernet.Eth1G;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.networklayer.configurator.ipv4.IPv4NetworkConfigurator;
import inet.applications.udpapp.UDPSink;
import inet_dns_extension.applications.traffic.WirelessMTGNodeWithTraffGen;
import inet_dns_extension.networks.dynamic_wireless_mdns_network.Sink;

network Dynamic_wireless_mtg_network
{
    parameters:
        int number_of_hosts;

        @display("bgb=1046,645");

    submodules:
        mtg_host[number_of_hosts]: WirelessMTGNodeWithTraffGen;
        multicast_router: Router {
            multicastForwarding = true;
            numRadios = 1;
            @display("p=394,314");
        }

        sink: Sink {
            parameters:
                @display("p=280,344;i=device/laptop");
        }

        ap: AccessPoint {
            @display("p=517,303");
        }

        radioMedium: Ieee80211ScalarRadioMedium {
            parameters:
                @display("p=100,50");
        }

        configurator: IPv4NetworkConfigurator {
            config = xmldoc("config.xml");
            @display("p=121,37");
        }
}