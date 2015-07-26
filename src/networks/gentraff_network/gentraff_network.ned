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

package inet_dns_extension.networks.gentraff_network;

import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.applications.udpapp.UDPSink;
import inet_dns_extension.applications.traffic.GenericTraffGenNode;
import inet.networklayer.configurator.ipv4.IPv4NetworkConfigurator;
import inet.node.ethernet.Eth1G;

network Gentraff_network
{
    parameters:
    	@display("bgb=894,645");
    	int num_clients = default(10);
    	
    submodules:
        sink: Sink {
            parameters:
                @display("p=280,344;i=device/laptop");
        }
        
        clients[num_clients]: GenericTraffGenNode{
        }
        
        configurator: IPv4NetworkConfigurator {
            @display("p=121,37");
        }
    connections:
        for i=0..num_clients-1{
        	clients[i].ethg++ <--> Eth1G <--> sink.ethg++;
        }
        
}

module Sink extends StandardHost{
    parameters:
       hasUdp = true;
	submodules:
	   udpSink: UDPSink{
	   	localPort = 8888;
	   }
	connections:
	   udp.appOut++ --> udpSink.udpIn;
	   udp.appIn++ <-- udpSink.udpOut;
}