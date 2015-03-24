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
#include <IPvXAddress.h>
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

namespace ODnsExtension {

enum ProbeState {
    STARTING, PROBING, ANNOUNCING, ANNOUNCED
};

enum AnnouncerState {
    START, RESTART, PROBE, SLEEP, FINISHED
};

struct Probe {
    uint32_t probe_id;
    ODnsExtension::TimeEvent* e;
    std::shared_ptr<ODnsExtension::DNSRecord> r;
    int n_iter = 0;
    int collision_count = 1;

    std::shared_ptr<MDNSService> ref_service;
    ProbeState s;

    Probe() :
            probe_id(0), e(NULL), r(NULL), n_iter(0), collision_count(1), ref_service(
                    NULL), s(STARTING) {
    }
    ;
};

class MDNSAnnouncer {
protected:
    ODnsExtension::TimeEventSet* timeEventSet;
    ODnsExtension::DNSTTLCache* auth_cache; // this cache is used for successfully
    ODnsExtension::MDNSProbeScheduler* probe_scheduler;
    ODnsExtension::MDNSResponseScheduler* response_scheduler;

    IPvXAddress* hostaddress;
    std::string hostname;
    std::string target;

    int id_internal = 0;
    int num_announced_jobs = 0;

    AnnouncerState s;

    std::unordered_map<int, std::string> probe_to_cache; // lookup of services in cache
    std::vector<std::shared_ptr<MDNSService>> to_announce; // this is a list consisting of MDNSService structs that have to be published
    std::vector<std::shared_ptr<Probe>> probing;  // probing list, when starting

public:
    MDNSAnnouncer(ODnsExtension::MDNSProbeScheduler* _probe_scheduler,
            ODnsExtension::MDNSResponseScheduler* _response_scheduler,
            ODnsExtension::TimeEventSet* _timeEventSet, std::vector<std::shared_ptr<MDNSService>> services,
            std::string _hostname, IPvXAddress* _hostaddress) {
        probe_scheduler = _probe_scheduler;
        response_scheduler = _response_scheduler;
        timeEventSet = _timeEventSet;
        to_announce = services;
        hostname = _hostname;
        hostaddress = _hostaddress;
        s = AnnouncerState::START;
    }
    virtual ~MDNSAnnouncer() {

    }

    virtual void initialize();
    virtual void restart();
    virtual int check_conflict(std::shared_ptr<DNSRecord> r);
    virtual void add_service(std::shared_ptr<MDNSService> service);
    virtual std::list<std::shared_ptr<DNSRecord>> get_announced_services();
    virtual void elapse(ODnsExtension::TimeEvent* e, void* data);
    virtual void withdraw(std::shared_ptr<Probe> p);
    virtual void goodbye(std::shared_ptr<Probe> p, int send_goodbye, int remove);

    virtual int getNumAnnounced() {
        return num_announced_jobs;
    }

    virtual AnnouncerState getState() {
        return s;
    }

    virtual ODnsExtension::DNSTTLCache* getCache() {
        return auth_cache;
    }

    static void elapseCallback(ODnsExtension::TimeEvent* e, void* data,
            void* thispointer) {
        MDNSAnnouncer* self = static_cast<MDNSAnnouncer*>(thispointer);
        self->elapse(e, data);
    }
};

#define MDNS_PROBE_TIMEOUT 250 // timeout for probing

} /* namespace ODnsExtension */

#endif /* MDNSANNOUNCER_H_ */
