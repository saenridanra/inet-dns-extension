/* Copyright (c) 2014-2015 Andreas Rain

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 */

#include <MDNSNetworkConfigurator.h>

Define_Module(MDNSNetworkConfigurator);

#define T(CODE)  {long startTime=clock(); CODE; printElapsedTime(#CODE, startTime);}

static void printElapsedTime(const char *name, long startTime)
{
    EV_INFO << "Time spent in IPv4NetworkConfigurator::" << name << ": "
            << ((double) (clock() - startTime) / CLOCKS_PER_SEC) << "s" << endl;
}

void MDNSNetworkConfigurator::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == inet::INITSTAGE_LOCAL)
    {
        // intialize params
        traffic_model = par("traffic_model").stdstringValue();
        distribution = par("distribution").stdstringValue();

        num_resolvers = (int) par("num_resolvers").longValue();
        num_private = (int) par("num_private").longValue();
        max_friends = (int) par("max_friends").longValue();
        min_friends = (int) par("min_friends").longValue();
        max_services = (int) par("max_services").longValue();
        min_services = (int) par("min_services").longValue();
        private_service_ratio = par("private_service_ratio").doubleValue();
        average_uptime = par("average_uptime").doubleValue();
        max_online_duration = par("max_online_duration").doubleValue();
        querying_enabled = par("querying_enabled").boolValue();

        std::string service_usage = par("service_usage_probability").stdstringValue();
        if (service_usage == "GAUSSIAN")
        {
            service_usage_probability = GAUSSIAN;
        }

        num_generated_services = 0;

    }
    else if (stage == inet::INITSTAGE_APPLICATION_LAYER)
    { // init in stage 3, after address have been assigned, but before
      // resolvers have been initialized

      // compute network
        T(computeMDNSNetwork());
    }
}

void MDNSNetworkConfigurator::pair(MDNSResolver * m1, MDNSResolver * m2,
        std::string device_name1, std::string device_name2, std::string instance_name1, std::string instance_name2)
{
    std::shared_ptr<INETDNS::FriendData> fdata;
    std::shared_ptr<INETDNS::PairingData> pdata;
    // migrate fdata, pdata
    pdata = INETDNS::pairing_data_new("", device_name2, instance_name2);
    fdata = INETDNS::friend_data_new(pdata, 9977); // use default port
    m1->addFriend(fdata);

    pdata = INETDNS::pairing_data_new("", device_name1, instance_name1);
    fdata = INETDNS::friend_data_new(pdata, 9977); // use default port
    m2->addFriend(fdata);
#ifdef DEBUG_ENABLED
    std::cout << "Paired " << device_name1 << " with " << device_name2 << std::endl;
#endif
}

void MDNSNetworkConfigurator::share(MDNSResolver * m1, MDNSResolver * m2,
        std::string device_name1, std::string device_name2,
        std::shared_ptr<MDNSNetworkConfigurator::GeneratorService> service)
{
    // Create private service
    std::shared_ptr<INETDNS::PrivateMDNSService> pservice = INETDNS::private_service_new(service->service,
            1);
    m1->addPrivateService(pservice);

    // add offers
    m1->addOfferedTo(pservice, device_name2);
    m2->addOfferedBy(pservice, device_name1);
}

std::shared_ptr<MDNSNetworkConfigurator::GeneratorService> MDNSNetworkConfigurator::generateNextService()
{
    std::shared_ptr<MDNSNetworkConfigurator::GeneratorService> gsrv(new MDNSNetworkConfigurator::GeneratorService);
    gsrv->service = std::string("_service") + std::to_string(num_generated_services) + std::string("._tcp.local");
    gsrv->port = intuniform(22, 32768);

    gsrv->probability = intuniform(10, 100);
    gsrv->is_private = intuniform(0, 100) <= private_service_ratio;
    num_generated_services++;
    return gsrv;
}

bool MDNSNetworkConfigurator::computeMDNSNetwork()
{
    // get all MDNS resolvers first
    std::vector<std::string> type_names;
    type_names.push_back("inet_dns_extension.applications.mdns.MDNSResolver");
    topology.extractByNedTypeName(type_names);
    EV_DEBUG << "Topology found " << topology.getNumNodes() << " nodes\n";
    // assert num resolvers, against the amount found in the toplogy
    if (num_resolvers != topology.getNumNodes())
        throw cRuntimeError("Amount of resolvers in the topology doesn't match the specified amount.");

    // initiliaze the device map
    for (int i = 0; i < topology.getNumNodes(); i++)
    {
        inet::Topology::Node *node = (inet::Topology::Node *) topology.getNode(i);
        cModule *module = node->getModule();
        // test that it's really a MDNSResolver..
        MDNSResolver *resolver = (MDNSResolver *) (module);

        // add the device to the map, keep a link
        // assign device names using variable i
        std::string device_name = "device" + std::to_string(i);
        device_map[device_name] = resolver;

        std::vector<std::shared_ptr<std::pair<SimTime, SimTime>>>timingSchedule;
        std::string start_str = std::to_string(intuniform(10, 20)) + std::string("s");
        std::string end_str = std::to_string(intuniform(3600, 7200)) + std::string("s");
        simtime_t start = STR_SIMTIME(start_str.c_str());
        simtime_t end = STR_SIMTIME(end_str.c_str());
        std::shared_ptr<std::pair<SimTime, SimTime>> p = std::shared_ptr<std::pair<SimTime, SimTime>>(
                new std::pair<SimTime, SimTime>(start, end));
        timingSchedule.push_back(p);
        resolver->setTimingSchedule(timingSchedule);
    }

    // pick a random selection of resolvers to be private
    int num_picked = 0;
    std::unordered_map<int, bool> selection;
    while (num_picked < num_private)
    {
        int pick = intuniform(0, num_resolvers - 1);
        if (selection[pick])
            continue;
        // has not been picked yet
        selection[pick] = true;
        num_picked++;
        // set hasPrivacy to true
        std::string device_name = std::string("device") + std::to_string(pick);
        std::string own_instance_name = device_name;
        MDNSResolver * resolver = device_map[device_name];

#ifdef DEBUG_ENABLED
        std::cout << "Adding device " << device_name << " with private instance " << own_instance_name << std::endl;
#endif
        resolver->setDynamicParams(device_name, own_instance_name, true, querying_enabled);

        private_device_map[device_name] = device_map[device_name];

        // not private, we can directly add it to the resolver
        // build service, add it to the resolver
        std::shared_ptr<INETDNS::MDNSService> s(new INETDNS::MDNSService);
        s->service_type = "_privacy._tcp.local";
        s->name = device_name;
        s->port = 9977;
        resolver->addService(s);
    }

    // set dynamic params on all other resolvers
    for (int i = 0; i < topology.getNumNodes(); i++)
    {
        if (selection[i])
            continue;
        std::string device_name = "device" + std::to_string(i);
        MDNSResolver * resolver = device_map[device_name];
        resolver->setDynamicParams(device_name, "", false, querying_enabled);
    }

    // now params have been set, add pairings
    // use topology to find out which nodes are actually connected
    std::unordered_map<std::string, bool> links; // map to remember which links have been set.
    // go through all devices
    for (auto device : private_device_map)
    {
        std::string device_name = device.first;
        MDNSResolver * resolver = device.second;
        std::string instance_name1 = device_name + "._privacy._tcp.local";

        // randomly pick other private resolvers..
        int to_pick;
        if (pairing_map[device_name].empty())
        {
            num_picked = 0;
            to_pick = intuniform(min_friends, max_friends);
        }
        else
        {
            num_picked = pairing_map[device_name].size();
            to_pick = intuniform(pairing_map[device_name].size(), max_friends);
        }

        while (num_picked < to_pick)
        {
            // pick friends randomly
            int pick = intuniform(0, num_resolvers - 1);
            if (selection[pick])
            {
                // private resolver picked..
                std::string picked_device_name = "device" + std::to_string(pick);

                if (device_name == picked_device_name)
                    continue;

                std::string instance_name2 = picked_device_name + "._privacy._tcp.local";
                // make sure the resolver still has space left
                // and the link is not already set
                if (pairing_map[picked_device_name].size() >= (uint32_t) max_friends)
                    break;
                else if (links.find(device_name + picked_device_name) != links.end())
                    continue;

                // this resolver still has place to be matched
                MDNSResolver * picked_resolver = device_map[picked_device_name];

                pair(resolver, picked_resolver, device_name, picked_device_name, instance_name1, instance_name2);
                // add links to the map, bidirectional
                links[device_name + picked_device_name] = true;
                links[picked_device_name + device_name] = true;

                // push the resolvers device name into the pairing map of the device
                // and vice versa to ensure mutuality
                pairing_map[device_name].push_back(picked_device_name);
                pairing_map[picked_device_name].push_back(device_name);

                num_picked++;
            }
            else
            {
                continue; // not private
            }

        }
    }

    // now generate max_services services and set them randomly on devices.
    for (int i = 0; i < max_services; i++)
    {
        std::shared_ptr<MDNSNetworkConfigurator::GeneratorService> service = generateNextService();
        // Remember which resolvers have been visited already
        // initially all are false

        for (int j = 0; j < num_resolvers; j++)
        {
            std::string device_name = "device" + std::to_string(j);
            MDNSResolver * resolver = device_map[device_name];

            // make random choice whether this service should be used
            // choice is based on the probability of a service to be used
            // and uniformly distributed
            /*int use = intuniform(0, 100);
            if (use > service->probability)
            {
                if (service->is_private) // remove the service if it was added before..
                    resolver->removePrivateService(service->service);
                continue;
            }*/

            // make a choice, whether the service should be announced privately
            int use_private = 0;
            if (service->is_private)
            {
                use_private = 1;
            }
            else
            {
                resolver->removePrivateService(service->service);
            }

            if (use_private)
            {
                // pick random subset of friends ...

                std::list<std::string> pairs = pairing_map[device_name];
                // choose subset of friends to share with
                // i.e., go through friend, randomly choose to share or not share
                for (auto f : pairs)
                {
                    // share with 50% of friends
                    int share_with_friend = intuniform(0, 1);
                    if (!share_with_friend)
                        continue;

                    MDNSResolver * picked_resolver = device_map[f];

#ifdef DEBUG_ENABLED
                    std::cout << "device " << device_name << " shares " << service->service << " with " << f
                            << std::endl;
#endif
                    share(resolver, picked_resolver, device_name, f, service);
                }
            }
            // not private, we can directly add it to the resolver
            // build service, add it to the resolver
            std::shared_ptr<INETDNS::MDNSService> s(new INETDNS::MDNSService);
            s->service_type = service->service;
            s->name = device_name;
            s->port = service->port;
            resolver->addService(s);
        }
    }

    return true;

}

MDNSNetworkConfigurator::~MDNSNetworkConfigurator(){
}
