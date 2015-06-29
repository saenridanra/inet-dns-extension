// Copyright (c) 2014 Andreas Rain

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

package inet_dns_extension.networks;

import inet_dns_extension.applications.dns.DNSAuthServer;
import inet.node.ethernet.Eth1G;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet_dns_extension.applications.dns.DNSServerNode;
import inet_dns_extension.applications.dns.DNSClientNode;
import inet.transportlayer.contract.IUDP;
import inet.networklayer.configurator.ipv4.IPv4NetworkConfigurator;
import inet_dns_extension.applications.dns.DNSClientTraffGen;

network SimpleDNSNetwork
{
    @display("bgb=1071,606");
    submodules:
        dns1: DNSServerNode {
            parameters:
                m_file = "pan.rz.uni-konstanz.de.zone";
                @display("p=532,303");
        }
        cli1: DNSClientNode {
            @display("p=403,303");
        }
        configurator: IPv4NetworkConfigurator {
            @display("p=121,37");
        }

        router: Router {
            @display("p=477,206");
        }
    connections:
        cli1.ethg++ <--> Eth1G <--> router.ethg++;
        dns1.ethg++ <--> Eth1G <--> router.ethg++;
}
