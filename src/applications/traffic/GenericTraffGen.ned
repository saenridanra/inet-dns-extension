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

//
// TODO auto-generated module
//
simple GenericTraffGen
{
    parameters:
        double minApps = default(1.0);
        double maxApps = default(5.0);
        double minBps = default(4096); // minimum of 500 bytes per second
        double maxBps = default(8000000); // maximum of 1MBs

        bool hasUDP = default(true);
        bool hasTCP = default(false);
        bool hasCBR = default(true);
        bool hasBURST = default(false);

        bool dynamicApps = default(false);

        string sink;
        
        int udpStandardPort = default(8888);
        int tcpStandardPort = default(9999);
        
    gates:
        input udpAppIn @labels(UDPControlInfo/down);
        output udpAppOut @labels(UDPControlInfo/down);
        input tcpAppIn @labels(UDPControlInfo/down);
        output tcpAppOut @labels(UDPControlInfo/down);
}