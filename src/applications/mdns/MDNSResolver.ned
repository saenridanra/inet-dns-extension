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

simple MDNSResolver
{
    parameters:
        @signal[mdnsQueryRcvd](type=cPacket);
        @signal[mdnsQuerySent](type=cPacket);
        @statistic[mdnsQuerySent](title="packets sent"; source=mdnsQuerySent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[mdnsQueryRcvd](title="packets received"; source=mdnsQueryRcvd; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @signal[mdnsResponseRcvd](type=cPacket);
        @signal[mdnsResponseSent](type=cPacket);
        @statistic[mdnsResponseSent](title="packets sent"; source=mdnsResponseSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[mdnsResponseRcvd](title="packets received"; source=mdnsResponseRcvd; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @signal[mdnsProbeRcvd](type=cPacket);
        @signal[mdnsProbeSent](type=cPacket);
        @statistic[mdnsProbeSent](title="packets sent"; source=mdnsProbeSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[mdnsProbeRcvd](title="packets received"; source=mdnsProbeRcvd; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        
        @signal[privateQueryRcvd](type=cPacket);
        @signal[privateQuerySent](type=cPacket);
        @statistic[privateQuerySent](title="packets sent"; source=privateQuerySent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[mdnsQueryRcvd](title="packets received"; source=privateQueryRcvd; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @signal[privateResponseRcvd](type=cPacket);
        @signal[privateResponseSent](type=cPacket);
        @statistic[privateResponseSent](title="packets sent"; source=privateResponseSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[privateResponseRcvd](title="packets received"; source=privateResponseRcvd; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @signal[privateProbeRcvd](type=cPacket);
        @signal[privateProbeSent](type=cPacket);
        @statistic[privateProbeSent](title="packets sent"; source=privateProbeSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[privateProbeRcvd](title="packets received"; source=privateProbeRcvd; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        
        string hostname;
        string service_files;
        string privacy_service_files;
        string pairing_data;
        string own_instance_name;
        string interfaceTableModule;
        
        // Domain Space Name Extension
        bool usesDSNExtension = default(false);
        
        // Privacy Extension
        bool hasPrivacy       = default(false);
        
        // Whether the Resolver queries with mdns queries
        bool isQuerying       = default(false);
        
        // Whether it is statically generated or dynamically
        bool static_configuration = default(true);
        
    gates:
        input mdnsIn @labels(UDPControlInfo/down);
        output mdnsOut @labels(UDPControlInfo/down);
        input privacyIn @labels(UDPControlInfo/down);
        output privacyOut @labels(UDPControlInfo/down);
}
