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

package opp_dns_extension.applications.mdns;

import inet.nodes.inet.StandardHost;
import opp_dns_extension.applications.mdns.MDNSResolver;
import inet.transport.IUDP;

module MDNSNode extends StandardHost
{
    parameters:
        hasUdp = true;
		string hname = default("Dummy");
		string sfile = default("");
    submodules:
        resolver: MDNSResolver {
            parameters:
                hostname = hname;
                service_files = sfile;
                @display("p=437,93");
        }
    connections:
        resolver.mdnsOut --> udp.appIn++;
        resolver.mdnsIn <-- udp.appOut++;
}
