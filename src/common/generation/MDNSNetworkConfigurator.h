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

#ifndef MDNSNETWORKCONFIGURATOR_H_
#define MDNSNETWORKCONFIGURATOR_H_

#include <omnetpp.h>
#include "INETDefs.h"

#include <Topology.h>
#include <MDNSResolver.h>
#include <MDNS.h>
#include <MDNS_Privacy.h>
#include <memory>

#include <string>
#include <list>
#include <vector>
#include <utility>
#include <unordered_map>
#include <iostream>

/**
 * @brief This class provides the means to configure an MDNS network.
 *
 * Based on the parameters, the resolvers are initialized and paired.
 *
 */
class MDNSNetworkConfigurator : public cSimpleModule {
    protected:

        /**
         * @brief This enum determines which distribution to use within this configuration.
         */
        enum Distributions {GAUSSIAN};

        /**
         * @brief Set the type of traffic generation for non-multicast traffic
         *
         * - CBR means constant bitrate
         * - Burst means that bursts of traffic are sent out
         * - Poisson follows a poisson distribution of traffic
         *
         */
        enum TrafficModels {CBR, BURST, POISSON};

        /**
         * @brief A helper struct to generate services
         */
        struct GeneratorService{
                std::string service;
                int port;
                int probability;
                bool is_private;
        };

        /**
         * @brief Set the overall amount of resolvers in the network.
         */
        int num_resolvers;

        /**
         * @brief Set the amount of private enabled resolvers.
         */
        int num_private;

        /**
         * @brief Set how many "friends" a private resolver maximally has.
         */
        int max_friends;

        /**
         * @brief Set how many "friends" a private resolver minimally has.
         */
        int min_friends;

        /**
         * @brief Set how many services a resolver maximally has.
         */
        int max_services;

        /**
         * @brief Set how many services a private resolver minimally has.
         */
        int min_services;

        /**
         * @brief Set the ratio of public to private services for the network.
         */
        double private_service_ratio;

        /**
         * @brief The current amount of generated services
         */
        int num_generated_services;

        /**
         * @brief Set the average uptime of a resolver (offline-online-offline)
         */
        simtime_t average_uptime;

        /**
         * @brief Set a limit on how long a resolver can be online
         */
        simtime_t max_online_duration;

        /**
         * @brief Keep the topology of @ref MDNSResolvers to configure the resolvers.
         */
        inet::Topology topology;

        /**
         * @brief Whether the resolvers can query or not
         */
        bool querying_enabled;

        /**
         * @brief Maps device names to modules, set on the resolvers
         */
        std::unordered_map<std::string, MDNSResolver *> device_map;

        /**
         * @brief Maps device names to modules, set on the resolvers
         */
        std::unordered_map<std::string, MDNSResolver *> private_device_map;

        /**
         * @brief Maps devices to list of devices
         *
         * that are considered to be paired with the key device.
         * The upper limit of the size map is defined by the member
         * max_friends. The lower limit by min_friends.
         */
        std::unordered_map<std::string, std::list<std::string>> pairing_map;

        /**
         * @brief Probability that a device will choose to use a service
         *
         * Uses enum of @ref Distributions
         */
        int service_usage_probability;

        /**
         * @brief Set the distribution used on some of the parameters
         */
        std::string distribution;

        /**
         * @brief Set the type of traffic generation for non-multicast traffic
         *
         * - CBR means constant bitrate
         * - Burst means that bursts of traffic are sent out
         * - Poisson follows a poisson distribution of traffic
         */
        std::string traffic_model;

        /**
         * @brief Takes two @ref MDNSResolver and creates a mutual pairing.
         *
         * @param m1 First MDNSResolver
         * @param m2 Second MDNSResolver
         * @param device_name1 First device name, used as m2's friend id of m1
         * @param device_name2 Second device name, used as m1's friend id of m2
         * @param instance_name1 First instance name, used as m2's reference for m1
         * @param instance_name2 Second instance name, used as m1's reference for m2
         *
         */
        void pair(MDNSResolver * m1, MDNSResolver * m2, std::string device_name1, std::string device_name2, std::string instance_name1, std::string instance_name2);

        /**
         * @brief Makes two @ref MDNSResolver share a service between each other
         */
        void share(MDNSResolver * m1, MDNSResolver * m2, std::string device_name1, std::string device_name2, std::shared_ptr<MDNSNetworkConfigurator::GeneratorService> service);

        /**
         * @brief Creates the next random service
         *
         * @return returns a struct @ref GeneratorService
         */
        std::shared_ptr<MDNSNetworkConfigurator::GeneratorService> generateNextService();


    public:
        ~MDNSNetworkConfigurator();
        virtual int numInitStages() const  { return inet::NUM_INIT_STAGES; }
        virtual void handleMessage(cMessage *msg) { throw cRuntimeError("this module doesn't handle messages, it runs only in initialize()"); }
        virtual void initialize(int stage);

        /**
         * @brief Computes the parameters for resolvers given the parameters.
         *
         * @return true if the network was properly computed.
         */
        bool computeMDNSNetwork();

};


#endif
