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


#ifndef __OPP_DNS_EXTENSION_MDNSRESOLVER_H_
#define __OPP_DNS_EXTENSION_MDNSRESOLVER_H_

#include <omnetpp.h>
#include <TimeEventSet.h>
#include "UDPControlInfo_m.h" // to get the src address
#include "UDPSocket.h"
#include "IPvXAddressResolver.h"

#include <DNSCache.h>
#include <DNSTTLCache.h>
#include <DNSTools.h>
#include <DNS.h>

#include <MDNSProbeScheduler.h>
#include <MDNSResponseScheduler.h>
#include <MDNSQueryScheduler.h>
#include <MDNSAnnouncer.h>

#include <MDNS_Privacy.h>

#include <vector>
#include <list>
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
class MDNSResolver : public cSimpleModule
{
  protected:
    /**
     * @brief @ref TimeEventSet used for managing events/callbacks.
     */
    ODnsExtension::TimeEventSet* timeEventSet;

    /**
     * @brief @ref ODnsExtension::MDNSProbeScheduler used for sending probes.
     */
    ODnsExtension::MDNSProbeScheduler* probeScheduler;

    /**
     * @brief @ref ODnsExtension::MDNSResponseScheduler used for sending responses.
     */
    ODnsExtension::MDNSResponseScheduler* responseScheduler;

    /**
     * @brief @ref ODnsExtension::MDNSQueryScheduler used for sending queries.
     */
    ODnsExtension::MDNSQueryScheduler* queryScheduler;

    /**
     * @brief @ref ODnsExtension::MDNSAnnouncer used for announcing services.
     */
    ODnsExtension::MDNSAnnouncer* announcer;

    /**
     * @brief @ref ODnsExtension::AnnouncerState , the state in which the announcer currently is.
     */
    ODnsExtension::AnnouncerState announcer_state;

    /**
     * @brief A ttl based cache used for storing responses from other resolvers.
     */
    ODnsExtension::DNSTTLCache* cache;

    /**
     * @brief Socket over which DNS queries are sent/received.
     */
    UDPSocket outSock;

    /**
     * @brief Socket over which private DNS queries are sent/received.
     */
    UDPSocket privacySock;

    /**
     * @brief Vector of @ref MDNSService , that need to be published.
     */
    std::vector<std::shared_ptr<ODnsExtension::MDNSService>> services;

    /**
     * @brief The resolvers hostname as a string.
     */
    std::string hostname;

    /**
     * @brief The resolvers hostaddress as @ref IPvXAddress
     */
    IPvXAddress hostaddress;

    /**
     * @brief a selfmessage to schedule when the next event is due.
     */
    cMessage* selfMessage;

    /**
     * @brief A map from strings (service types) to @ref ODnsExtension::PrivateMDNSService .
     */
    std::unordered_map<std::string, std::shared_ptr<ODnsExtension::PrivateMDNSService>> *private_service_table;

    /**
     * @brief A map from strings (friend ids) to @ref ODnsExtension::FriendData .
     */
    std::unordered_map<std::string, std::shared_ptr<ODnsExtension::FriendData>> *friend_data_table;

    /**
     * @brief A map from strings (instance names) to @ref ODnsExtension::FriendData .
     */
    std::unordered_map<std::string, std::shared_ptr<ODnsExtension::FriendData>> *instance_name_table;

    /**
     * @brief The own instance name as a string.
     */
    std::string own_instance_name;

    /**
     * @brief Whether privacy functionality is activated or not.
     */
    bool hasPrivacy;

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

  public:
    MDNSResolver();
    ~MDNSResolver();
    virtual void initialize(int stage);
    virtual int numInitStages() const { return 4; }
    virtual void handleMessage(cMessage *msg);

    /**
     * @brief Callback used for @ref ODnsExtension::TimeEvent .
     *
     * When the timeevent is due, this callback is called.
     */
    static void callback(std::shared_ptr<void> data, void* thispointer);

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

#define MDNS_KIND_TIMER 0
#define MDNS_KIND_EXTERNAL 1
#define MDNS_KIND_INTERNAL_QUERY 2
#define MDNS_KIND_INTERNAL_PUBLISH 3
#define MDNS_KIND_INTERNAL_REVOKE 4

#endif
