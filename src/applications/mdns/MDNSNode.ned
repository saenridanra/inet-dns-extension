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

package inet_dns_extension.applications.mdns;

import inet.node.inet.StandardHost;
import inet_dns_extension.applications.mdns.MDNSResolver;
import inet.transportlayer.contract.IUDP;

module MDNSNode extends StandardHost
{
    parameters:
        hasUdp = true;
        
		string hname = default("Dummy");
		string sfile = default("");
		string privacy_sfile = default("");
		string pdata = default("");
        string own_instance = default("");
		
		bool private = default(false);
		bool querying = default(false);
		
    submodules:
        resolver: MDNSResolver {
            parameters:
                own_instance_name = own_instance;
                hasPrivacy = private;
                hostname = hname;
                service_files = sfile;
                privacy_service_files = privacy_sfile;
                pairing_data = pdata;
                isQuerying = querying;
                
                @display("p=437,93");
        }
    connections:
        resolver.mdnsOut --> udp.appIn++;
        resolver.mdnsIn <-- udp.appOut++;
        resolver.privacyOut --> udp.appIn++;
        resolver.privacyIn <--  udp.appOut++;
}
