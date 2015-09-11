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

package inet_dns_extension.applications.traffic;

import inet.node.inet.WirelessHost;
import inet_dns_extension.applications.traffic.MulticastTraffGen;
import inet_dns_extension.applications.traffic.GenericTraffGen;
import inet.transportlayer.contract.IUDP;

module WirelessMTGNode extends WirelessHost
{
    parameters:
        hasUdp = true;
    submodules:
        mtg: MulticastTraffGen {
            parameters:
                @display("p=437,93");
        }
    connections:
        mtg.udpAppOut --> udp.appIn++;
        mtg.udpAppIn <-- udp.appOut++;
}

module WirelessMTGNodeWithTraffGen extends WirelessHost
{
    parameters:
        hasUdp = true;
    submodules:
        mtg: MulticastTraffGen {
            parameters:
                @display("p=437,93");
        }
        
        gt: GenericTraffGen {}
    connections:
        mtg.udpAppOut --> udp.appIn++;
        mtg.udpAppIn <-- udp.appOut++;
		gt.udpAppOut --> udp.appIn++;
		gt.udpAppIn <-- udp.appOut++;
}
