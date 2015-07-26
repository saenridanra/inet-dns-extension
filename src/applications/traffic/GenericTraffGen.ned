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
import inet.node.inet.StandardHost;
import inet.transportlayer.contract.IUDP;

//
// TODO auto-generated module
//
simple GenericTraffGen
{
    parameters:
        double minApps = default(1.0);
        double maxApps = default(25.0);
        double minBps = default(512); // minimum of 500 bytes per second
        double maxBps = default(8000000); // maximum of 1MBs
        
        bool hasCBR = default(true);
        bool hasBURST = default(false);
        bool hasLRD = default(false);
        
        double lrdParetoAlpha = default(1.5);
        double lrdParetoBeta = default(0.1);

        bool dynamicApps = default(false);

        string sink;
        
        int udpStandardPort = default(8888);
        int tcpStandardPort = default(9999);
        
        int appInterArrivalMean = default(1);
        int appServiceTimeMean = default(1);
        
        bool   recordThruput                = default(false);
        double recordThruputScale @unit(ms) = default(1ms); // Scale on which to record thruput
        string recordThruputFileColDelimiter   = default("\t");
        
    gates:
        input udpAppIn @labels(UDPControlInfo/down);
        output udpAppOut @labels(UDPControlInfo/down);
        input tcpAppIn @labels(UDPControlInfo/down);
        output tcpAppOut @labels(UDPControlInfo/down);
}

module GenericTraffGenNode extends StandardHost{
    parameters:
        hasUdp = true;
    	@display("p=432,344;i=device/laptop");
    	
    submodules:
        gt: GenericTraffGen {
        }
        
    connections:
		gt.udpAppOut --> udp.appIn++;
		gt.udpAppIn <-- udp.appOut++;
}