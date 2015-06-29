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

#ifndef MDNSTRAFFICGENERATOR_H_
#define MDNSTRAFFICGENERATOR_H_

#include <omnetpp.h>
#include <UDPSocket.h>
#include <L3AddressResolver.h>
#include <DNS.h>
#include <DNSTools.h>
#include <MDNS.h>
#include <MDNS_Privacy.h>
#include <MDNSProbeScheduler.h>
#include <MDNSQueryScheduler.h>
#include <MDNSResponseScheduler.h>

#include <vector>

namespace INETDNS {

/**
 * @brief This class generates services dynamically, while a resolver is running.
 *
 * It also queries for other services based on specified parameters.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date June 1, 2015
 */
class MDNSTrafficGenerator
{
    protected:
        bool RUNNING;

        /**
         * @brief List of services this traff gen queries for.
         */
        std::vector<std::string> serviceList;

        /**
         * @brief @ref TimeEventSet used for managing events/callbacks.
         */
        INETDNS::TimeEventSet* timeEventSet;

        /**
         * @brief Remember the event that was scheduled latest.
         */
        INETDNS::TimeEvent* latestScheduledEvent;

        /**
         * @brief @ref ODnsExtension::MDNSProbeScheduler used for sending probes.
         */
        INETDNS::MDNSProbeScheduler* probeScheduler;

        /**
         * @brief @ref ODnsExtension::MDNSResponseScheduler used for sending responses.
         */
        INETDNS::MDNSResponseScheduler* responseScheduler;

        /**
         * @brief @ref ODnsExtension::MDNSQueryScheduler used for sending queries.
         */
        INETDNS::MDNSQueryScheduler* queryScheduler;

        /**
         * @brief Socket over which DNS queries are sent/received.
         */
        inet::UDPSocket* outSock;

        /**
         * @brief Socket over which private DNS queries are sent/received.
         */
        inet::UDPSocket* privacySock;

        /**
         * @brief Local multicast address in use.
         */
        inet::L3Address multicast_address = inet::L3AddressResolver().resolve("225.0.0.1");

        /**
         * @brief A map from strings (service types) to @ref ODnsExtension::PrivateMDNSService .
         */
        std::unordered_map<std::string, std::shared_ptr<INETDNS::PrivateMDNSService>> *private_service_table;

        /**
         * @brief A map from strings (friend ids) to @ref ODnsExtension::FriendData .
         */
        std::unordered_map<std::string, std::shared_ptr<INETDNS::FriendData>> *friend_data_table;

        /**
         * @brief A map from strings (instance names) to @ref ODnsExtension::FriendData .
         */
        std::unordered_map<std::string, std::shared_ptr<INETDNS::FriendData>> *instance_name_table;

        /**
         * @brief Whether privacy extenstion is active.
         */
        int hasPrivacy = 0;

    public:
        MDNSTrafficGenerator(INETDNS::MDNSProbeScheduler* probeScheduler,
                INETDNS::MDNSQueryScheduler* queryScheduler,
                INETDNS::MDNSResponseScheduler* responseScheduler, INETDNS::TimeEventSet* timeEventSet,
                inet::UDPSocket* outSock, std::vector<std::string> serviceList)
        {
            this->probeScheduler = probeScheduler;
            this->queryScheduler = queryScheduler;
            this->responseScheduler = responseScheduler;
            this->timeEventSet = timeEventSet;
            this->outSock = outSock;
            this->serviceList = serviceList;
        }
        ~MDNSTrafficGenerator();

        /**
         * @brief Set the privacy information, i.e. services, friend data..
         *
         * @param private_service_table Table containing information about private services.
         * @param friend_data_table Table containing friend data.
         * @param instance_name_table Mapping of instance names to friend data.
         * @param privacySocket Set the output socket for output data
         */
        virtual void setPrivacyData(
                std::unordered_map<std::string, std::shared_ptr<PrivateMDNSService>>* private_service_table,
                std::unordered_map<std::string, std::shared_ptr<FriendData>>* friend_data_table,
                std::unordered_map<std::string, std::shared_ptr<FriendData>>* instance_name_table,
                inet::UDPSocket* privacySocket)
        {
            this->private_service_table = private_service_table;
            this->friend_data_table = friend_data_table;
            this->instance_name_table = instance_name_table;
            this->privacySock = privacySocket;
            hasPrivacy = 1;
        }

        /**
         * @brief Static callback function, called when an event expires.
         *
         * @param e Event that triggered the callback.
         * @param data Smart pointer to void data, in this case @ref Probe
         * @param thispointer A reference to the handle that created the event.
         */
        static void elapseCallback(INETDNS::TimeEvent* e, std::shared_ptr<void> data, void* thispointer)
        {
            MDNSTrafficGenerator* self = static_cast<MDNSTrafficGenerator*>(thispointer);
            self->elapse(e, data);
        }

        /**
         * @brief Starts querying for services.
         */
        virtual void startQuerying();

        /**
         * @brief Stops querying for services.
         */
        virtual void stopQuerying();

    protected:
        /**
         * @brief Elapse method, when the next scheduled event is due.
         *
         * @param e Event that triggered the elapse
         * @param data smart pointer to void data, in this case always @ref Probe
         */
        virtual void elapse(INETDNS::TimeEvent* e, std::shared_ptr<void> data);

};

} /* namespace ODnsExtension */

#endif /* MDNSTRAFFICGENERATOR_H_ */
