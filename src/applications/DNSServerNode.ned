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

package opp_dns_extension.applications;

import inet.nodes.inet.StandardHost;
import opp_dns_extension.applications.DNSAuthServer;
import inet.transport.IUDP;

module DNSServerNode extends StandardHost
{
    parameters:
        hasUdp = true;
        string m_file;

    submodules:
        auth: DNSAuthServer {
            parameters:
                master_file = m_file;
        }
    connections:
        auth.udpOut --> udp.appIn++;
        auth.udpIn <-- udp.appOut++;
}