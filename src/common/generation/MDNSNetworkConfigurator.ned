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

package inet_dns_extension.common.generation;

simple MDNSNetworkConfigurator{
    parameters:
        
        string traffic_model = default("CBR");
        string distribution  = default("GAUSSIAN");
        
        int num_resolvers = default(10);
        int num_private = default(0);
        int max_friends = default(0);
        int min_friends = default(0);
        int max_services = default(4);
        int min_services = default(1);
        
        // Whether resolver query
        bool querying_enabled = default(false);
        
        // Domain Space Name Extension
        bool usesDSNExtension = default(false);
        
        string service_usage_probability = default("GAUSSIAN");
        
        double private_service_ratio = default(0.0);
        
        double average_uptime @unit(s) = default(600s);
        double max_online_duration @unit(s) = default(3600s);
}