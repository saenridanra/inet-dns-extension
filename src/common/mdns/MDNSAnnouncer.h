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

#ifndef MDNSANNOUNCER_H_
#define MDNSANNOUNCER_H_

#include <omnetpp.h>
#include <L3Address.h>
#include <TimeEventSet.h>
#include <DNS.h>
#include <DNSCache.h>
#include <DNSTTLCache.h>
#include <MDNS.h>
#include <MDNSResponseScheduler.h>
#include <MDNSProbeScheduler.h>

#include <iostream>
#include <vector>
#include <unordered_map>

namespace INETDNS {

/**
 * @brief Enum used to determine the probes state
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
enum ProbeState {
    STARTING, PROBING, ANNOUNCING, ANNOUNCED
};

/**
 * @brief Enum used to determine the announcers state
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
enum AnnouncerState {
    START, RESTART, PROBE, SLEEP, FINISHED
};

/**
 * @brief Structure holding information about probes that need to be announced.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
struct Probe {

    /**
     * @brief ID uniquely identifying the probe
     */
    uint32_t probe_id;

    /**
     * @brief A @ref ODnsExtension::TimeEvent which performs the callback while scheduling probes.
     */
    INETDNS::TimeEvent* e;

    /**
     * @brief The record that needs to be published/probed.
     */
    std::shared_ptr<INETDNS::DNSRecord> r;

    /**
     * @brief the number of iterations already performed.
     */
    int n_iter = 0;

    /**
     * @brief the amount of collision while announcing this record.
     */
    int collision_count = 1;

    /**
     * @brief The @ref MDNSService for which this probe was generated.
     */
    std::shared_ptr<MDNSService> ref_service;

    /**
     * @brief the current state of the probe.
     */
    ProbeState s;

    Probe() :
            probe_id(0), e(NULL), r(NULL), n_iter(0), collision_count(1), ref_service(
                    NULL), s(STARTING) {
    }
    ;
};

/**
 * @brief Announces @ref MDNSService
 *
 * Announces services to the network via mdns.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class MDNSAnnouncer {
protected:

    /**
     * @brief @ref TimeEventSet used for managing events/callbacks.
     */
    INETDNS::TimeEventSet* timeEventSet;

    /**
     * @brief A ttl cache, in which annouced services are stored.
     *
     * They are republished once the TTL expires.
     */
    INETDNS::DNSTTLCache* auth_cache;

    /**
     * @brief @ref ODnsExtension::MDNSProbeScheduler used for sending probes.
     */
    INETDNS::MDNSProbeScheduler* probe_scheduler;

    /**
     * @brief @ref ODnsExtension::MDNSResponseScheduler used for sending responses.
     */
    INETDNS::MDNSResponseScheduler* response_scheduler;

    /**
     * @brief The resolvers hostaddress as @ref inet::L3Address of type IPv4
     */
    inet::L3Address* hostaddress4;

    /**
     * @brief The resolvers hostaddress as @ref inet::L3Address of type IPv6
     */
    inet::L3Address* hostaddress6;

    /**
     * @brief The resolvers hostname.
     */
    std::string hostname;

    /**
     * @brief The target used for services.
     *
     * Usually consists of hostname.local pointing to the hostaddress.
     */
    std::string target;

    /**
     * @brief Unique internal id to keep track of probes.
     */
    int id_internal = 0;

    /**
     * @brief A counter to keep track of announced records.
     */
    int num_announced_jobs = 0;

    /**
     * @brief Whether the Domain Space Name Extension is active or not
     */
    bool usesDSNExtension;

    /**
     * @brief The current state of the announcer.
     */
    AnnouncerState s;

    /**
     * @brief A cache mapping unique probe ids to hashs.
     */
    std::unordered_map<int, std::string> probe_to_cache; // lookup of services in cache

    /**
     * @brief Services that need to be announced.
     */
    std::vector<std::shared_ptr<MDNSService>> to_announce; // this is a list consisting of MDNSService structs that have to be published

    /**
     * @brief Currently probing probes.
     */
    std::vector<std::shared_ptr<Probe>> probing;  // probing list, when starting

public:
    /**
     * @brief Constructor for @ref MDNSAnnouncer
     *
     * @param _probe_scheduler The probe scheduler instantiated by the resolver
     * @param _response_scheduler The response scheduler instantiated by the resolver
     * @param _timeEventSet The timeeventset instantiated by the resolver
     * @param services Services that need to be published
     * @param _hostname The resolvers hostname
     * @param _hostaddress The resolvers hostaddress
     */
    MDNSAnnouncer(INETDNS::MDNSProbeScheduler* _probe_scheduler,
            INETDNS::MDNSResponseScheduler* _response_scheduler,
            INETDNS::TimeEventSet* _timeEventSet, std::vector<std::shared_ptr<MDNSService>> services,
            std::string _hostname, inet::L3Address* _hostaddress4, inet::L3Address* _hostaddress6, bool usesDSNExtension) {
        probe_scheduler = _probe_scheduler;
        response_scheduler = _response_scheduler;
        timeEventSet = _timeEventSet;
        to_announce = services;
        hostname = _hostname;
        hostaddress4 = _hostaddress4;
        hostaddress6 = _hostaddress6;
        s = AnnouncerState::START;
        this->usesDSNExtension = usesDSNExtension;
    }
    virtual ~MDNSAnnouncer() {

    }

    /**
     * @brief Initializes the Announcer
     */
    virtual void initialize();

    /**
     * @brief Restarts the announcer
     *
     * leading to revoking all services and republishing them
     * afterwards.
     */
    virtual void restart();

    /**
     * @brief Check if an incoming record is conflicting.
     *
     * Depending on the conflict, the record may be withdrawn
     * and republished with a new instance name.
     *
     * @return 1 if conflicting, 0 otherwise
     */
    virtual int check_conflict(std::shared_ptr<DNSRecord> r);

    /**
     * @brief Add a service that needs to be published
     * @param service The @ref MDNSService that needs publishing
     */
    virtual void add_service(std::shared_ptr<MDNSService> service);

    /**
     * @brief Retrieve the list of announced records
     *
     * @return List of announced @ref DNSRecord
     */
    virtual std::list<std::shared_ptr<DNSRecord>> get_announced_services();

    /**
     * @brief Elapse method, when the next scheduled event is due.
     *
     * @param e Event that triggered the elapse
     * @param data smart pointer to void data, in this case always @ref Probe
     */
    virtual void elapse(INETDNS::TimeEvent* e, std::shared_ptr<void> data);

    /**
     * @brief Withdraws a probe
     *
     * @param p Probe that needs to be withdrawn.
     */
    virtual void withdraw(std::shared_ptr<Probe> p);

    /**
     * @brief Revokes a published record
     *
     * by sending a goodbye record if the flag is set.
     *
     * @param p Probe that needs to be revoked.
     * @param send_goodbye Flag is set, if a record needs to be send.
     * @param remove If the flag is set, the probe is completely removed.
     */
    virtual void goodbye(std::shared_ptr<Probe> p, int send_goodbye, int remove);

    /**
     * @brief Turns of the announcer and send goodbye records
     */
    virtual void shutdown();

    /**
     * @brief Retrieve the amount of announced services
     *
     * @return amount of announced services
     */
    virtual int getNumAnnounced() {
        return num_announced_jobs;
    }

    /**
     * @brief Determine the current state of the announcer.
     *
     * @return @ref AnnouncerState
     */
    virtual AnnouncerState getState() {
        return s;
    }

    /**
     * @brief Retrieve the full cache of announced records.
     *
     * @return the Cache object.
     */
    virtual INETDNS::DNSTTLCache* getCache() {
        return auth_cache;
    }

    /**
     * @brief Static callback function, called when an event expires.
     *
     * @param e Event that triggered the callback.
     * @param data Smart pointer to void data, in this case @ref Probe
     * @param thispointer A reference to the handle that created the event.
     */
    static void elapseCallback(INETDNS::TimeEvent* e, std::shared_ptr<void> data,
            void* thispointer) {
        MDNSAnnouncer* self = static_cast<MDNSAnnouncer*>(thispointer);
        self->elapse(e, data);
    }
};

#define MDNS_PROBE_TIMEOUT 250 // timeout for probing

} /* namespace ODnsExtension */

#endif /* MDNSANNOUNCER_H_ */
