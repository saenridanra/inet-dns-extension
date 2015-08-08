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

#ifndef __INETDNS_MDNSRESOLVER_H_
#define __INETDNS_MDNSRESOLVER_H_

#include <omnetpp.h>
#include "INETDefs.h"
#include "ModuleAccess.h"
#include <TimeEventSet.h>
#include "UDPControlInfo_m.h" // to get the src address
#include "UDPSocket.h"
#include "L3AddressResolver.h"

#include <DNSCache.h>
#include <DNSTTLCache.h>
#include <DNSTools.h>
#include <DNS.h>

#include <MDNSProbeScheduler.h>
#include <MDNSResponseScheduler.h>
#include <MDNSQueryScheduler.h>
#include <MDNSAnnouncer.h>
#include <MDNSTrafficGenerator.h>
#include <SignalReceiver.h>

#include <MDNS_Privacy.h>

#include <regex>
#include <vector>
#include <list>
#include <utility>
#include <unordered_map>
#include <memory>
#include <iostream>
#include <fstream>

/**
 * @brief Provides functionality of a mdns resolver.
 *
 * New queries can be sent over the internal interface sending
 * a @ref cMessage to this module internally containing either message kinds:
 *
 * - @ref MDNS_KIND_INTERNAL_QUERY : used for queries
 * - @ref MDNS_KIND_INTERNAL_PUBLISH : used to publish own services dynamically
 * - @ref MDNS_KIND_INTERNAL_REVOKE : used to take down services
 *
 * Further operations may follow.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class MDNSResolver : public cSimpleModule, public SignalReceiver, public INETDNS::TimeEventSetObserver
{
    protected:
        enum MDNSResolverState
        {
            RUNNING, SHUTDOWN
        };

        /**
         * @brief @ref TimeEventSet used for managing events/callbacks.
         */
        INETDNS::TimeEventSet* timeEventSet;

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
         * @brief @ref ODnsExtension::MDNSAnnouncer used for announcing services.
         */
        INETDNS::MDNSAnnouncer* announcer;

        /**
         * @brief This class performs queries and simulates dynamic mdns traffic.
         */
        INETDNS::MDNSTrafficGenerator* mdnsTrafficGenerator;

        /**
         * @brief @ref ODnsExtension::AnnouncerState , the state in which the announcer currently is.
         */
        INETDNS::AnnouncerState announcer_state;

        /**
         * @brief A ttl based cache used for storing responses from other resolvers.
         */
        INETDNS::DNSTTLCache* cache;

        /**
         * @brief Socket over which DNS queries are sent/received.
         */
        inet::UDPSocket outSock;

        /**
         * @brief Socket over which private DNS queries are sent/received.
         */
        inet::UDPSocket privacySock;

        /**
         * @brief Vector of @ref MDNSService , that need to be published.
         */
        std::vector<std::shared_ptr<INETDNS::MDNSService>> services;

        /**
         * @brief The resolvers hostname as a string.
         */
        std::string hostname;

        /**
         * @brief The resolvers hostaddress as @ref inet::L3Address of type IPv4
         */
        inet::L3Address hostaddress4;

        /**
         * @brief The resolvers hostaddress as @ref inet::L3Address of type IPv6
         */
        inet::L3Address hostaddress6;

        /**
         * @brief a selfmessage to schedule when the next event is due.
         */
        cMessage* selfMessage;

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
         * @brief The own instance name as a string.
         */
        std::string own_instance_name;

        /**
         * @brief Whether the Domain Space Name Extension is active or not
         */
        bool usesDSNExtension;

        /**
         * @brief Whether privacy functionality is activated or not.
         */
        bool hasPrivacy;

        /**
         * @brief Whether this resolver has a traffic generator that queries for services.
         */
        bool isQuerying;

        /**
         * @brief The time of the last scheduled self message.
         *
         * It is used to quickly find out whether an upcoming event earlier due
         * and the self scheduled message needs to be updated.
         */
        simtime_t last_schedule;

        /**
         * @brief Time that needs to be elapsed before the first scheduled message.
         */
        simtime_t elapseTime = STR_SIMTIME("1ms");

        /**
         * @brief Determine, whether the module will be configured statically or dynamically.
         *
         * If false, then an @ref MDNSNetworkConfigurator has to be provided in order
         * to configure the resolver.
         */
        bool static_configuration;

        /**
         * @brief List of pairs containing the uptimes of this resolver.
         *
         * This is only used by the @ref MDNSNetworkConfigurator
         * which controls when a node in the network should be
         * online.
         */
        std::vector<std::shared_ptr<std::pair<SimTime, SimTime>>> uptimes;

        /**
         * @brief the position of the current uptime.
         */
        int current_uptime;

        /**
         * @brief The resolvers current state, needed for shutdown operations.
         */
        MDNSResolverState state;

        /**
         * This section defines different omnet++ signals.
         */
        static simsignal_t mdnsQueryRcvd;
        static simsignal_t mdnsQuerySent;
        static simsignal_t mdnsResponseRcvd;
        static simsignal_t mdnsResponseSent;
        static simsignal_t mdnsProbeRcvd;
        static simsignal_t mdnsProbeSent;

        static simsignal_t privateQueryRcvd;
        static simsignal_t privateQuerySent;
        static simsignal_t privateResponseRcvd;
        static simsignal_t privateResponseSent;
        static simsignal_t privateProbeRcvd;
        static simsignal_t privateProbeSent;


    public:
        MDNSResolver();
        ~MDNSResolver();
        virtual void initialize(int stage);
        virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
        virtual void handleMessage(cMessage *msg);

        /**
         * @brief Callback used for @ref ODnsExtension::TimeEvent .
         *
         * When the timeevent is due, this callback is called.
         */
        static void callback(std::shared_ptr<void> data, void* thispointer);

        /**
         * @brief Set params for the resolver dynamically.
         *
         * Used for dynamic configuration of a resolver.
         *
         * @param hostname String containing the hostname used to announce
         * @param own_instance_name The instance name this resolver shall use for announcments.
         * @param usesDSNExtension Whether Domain Space Name extension is activated.
         * @param hasPrivacy Whether privacy capabilities are enabled.
         * @param isQuerying Whether the resolver queries.
         */
        void setDynamicParams(std::string hostname, std::string own_instance_name, bool usesDSNExtension, bool hasPrivacy, bool isQuerying)
        {
            this->hostname = hostname;
            this->own_instance_name = own_instance_name;
            this->hasPrivacy = hasPrivacy;
            this->isQuerying = isQuerying;
        }

        /**
         * @brief Add a service this resolver needs to announce and resolve
         *
         * @param service Shared pointer to an @ref ODnsExtension::MDNSService that needs to be shared.
         */
        void addService(std::shared_ptr<INETDNS::MDNSService> service)
        {
            this->services.push_back(service);
        }

        /**
         * @brief Add a privacy enabled service to this resolver
         *
         * @param pService Shared pointer to a private mdns service structure
         */
        void addPrivateService(std::shared_ptr<INETDNS::PrivateMDNSService> pService)
        {
            std::cout << "Adding private service " << pService->service_type << std::endl;
            (*this->private_service_table)[pService->service_type] = pService;
        }

        /**
         * @brief Remove a private service from the table
         *
         * @param service_type Service typename to be deleted
         */
        void removePrivateService(std::string service_type)
        {
            if((*this->private_service_table).find(service_type) != private_service_table->end())
                (*this->private_service_table).erase((*this->private_service_table).find(service_type));
        }

        void addOfferedTo(std::shared_ptr<INETDNS::PrivateMDNSService> pService, std::string offered_to)
        {
            (*this->private_service_table)[pService->service_type]->offered_to.push_back(offered_to);
        }

        void addOfferedBy(std::shared_ptr<INETDNS::PrivateMDNSService> pService, std::string offered_by)
        {
            if (private_service_table->find(pService->service_type) != private_service_table->end())
            {
                (*private_service_table)[pService->service_type]->offered_by.push_back(offered_by);
            }
            else
            {
                // add hull
                std::shared_ptr<INETDNS::PrivateMDNSService> cpService(new INETDNS::PrivateMDNSService);
                cpService->service_type = pService->service_type;
                cpService->is_private = pService->is_private;
                // ignore txtrecord
                cpService->offered_by.push_back(offered_by);
                (*private_service_table)[cpService->service_type] = cpService;
            }
        }

        /**
         * @brief Add a trusted "friend" to the resolver.
         *
         * @param fdata Shared pointer to fully initialized @ref ODnsExtension::FriendData struct.
         */
        void addFriend(std::shared_ptr<INETDNS::FriendData> fdata)
        {
            // Map instance name to friend, as well as id
            (*friend_data_table)[fdata->pdata->friend_id] = fdata;
            (*instance_name_table)[fdata->pdata->privacy_service_instance_name] = fdata;
        }

        /**
         * @brief Set the timing schedule of up/downtimes
         *
         * @param timingSchedule Vector containing of pairs of @ref SimTime
         */
        void setTimingSchedule(std::vector<std::shared_ptr<std::pair<SimTime, SimTime>>> timingSchedule)
        {
            uptimes = timingSchedule;
        }

        /**
         * @brief Determine whether Domain Space Name Extension is used
         *
         * @return true if it is used.
         */
        bool hasDSNExtension(){
            return usesDSNExtension;
        }

        /**
         * @brief Determine whether this module has privacy activated.
         *
         * @return true if privacy is set.
         */
        bool isPrivate()
        {
            return hasPrivacy;
        }

        /**
         * @brief Pass a signal with parameters to the receiver
         *
         * In this case the resolver takes 2 parameters:
         *  - signal_type : {0 Probe sent, 1 Query sent, 2 Response sent}
         *  - privacy : {0 false, 1 true}
         *
         * @param parMap Map of flags
         * @param additionalPayload in this case the cPacket is passed
         */
        virtual void receiveSignal(std::unordered_map<std::string, int> parMap, void* additionalPayload);

        virtual void notify();

    protected:

        /**
         * @brief Handler for self messages of kind @ref MDNS_KIND_TIMER
         */
        virtual void elapsedTimeCheck();

        /**
         * @brief Handles a received query.
         *
         * According to RFC 6762 <http://tools.ietf.org/html/rfc6762>, performs
         * duplicate question suppression, known answer suppression and schedules
         * events according to recommended timings.
         *
         * @param p query packet
         */
        virtual void handleQuery(DNSPacket* p);

        /**
         * @brief Handles a received response.
         *
         * According to RFC 6762 <http://tools.ietf.org/html/rfc6762>, performs
         * duplicate answer suppression and schedules
         * events according to recommended timings.
         *
         * @param p response packet
         */
        virtual void handleResponse(DNSPacket* p);

        /**
         * @brief A convience method to schedule a new self message.
         *
         * The old self message is canceled and only then a new
         * self message is scheduled.
         */
        virtual void scheduleSelfMessage(simtime_t tv);

        /**
         * @brief Initializes @ref ODnsExtension::MDNSService from the configuation params.
         */
        virtual void initializeServices();

        /**
         * @brief Initializes @ref ODnsExtension::MDNSService a service file
         */
        virtual void initializeServiceFile(std::string file);

        /**
         * @brief Initializes private services
         *
         * and populates @ref private_service_table, @ref friend_data_table and @ref instance_name_table
         * and passes the tables to the schedulers.
         */
        virtual void initializePrivateServices();
};

static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static std::regex dsn_type_expr ("(.*)::[0-9A-Za-z]{16}(.*)");

#define MDNS_KIND_TIMER 0
#define MDNS_KIND_EXTERNAL 1
#define MDNS_KIND_INTERNAL_QUERY 2
#define MDNS_KIND_INTERNAL_PUBLISH 3
#define MDNS_KIND_INTERNAL_REVOKE 4

#endif
