// Copyright (c) 2014-2015 Andreas Rain

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package inet_dns_extension.applications.traffic;
import inet.node.inet.StandardHost;
import inet.transportlayer.contract.IUDP;

simple GenericTraffGen
{
    parameters:
        double minBps = default(512); // minimum of 500 bytes per second
        double maxBps = default(8000000); // maximum of 1MBs
        
        bool hasCBR = default(true);
        bool hasBURST = default(false);
        bool hasLRD = default(false);
        
        double lrdParetoAlpha = default(1.5);
        double lrdParetoBeta = default(0.1);

        string sink;
        
        int udpStandardPort = default(8888);
        int tcpStandardPort = default(9999);
        
        int appInterArrivalMean = default(3);
        int appServiceTimeMean = default(15);
        
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