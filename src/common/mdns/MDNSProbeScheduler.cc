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

#include <mdns/MDNSProbeScheduler.h>

namespace INETDNS {

MDNSProbeScheduler::MDNSProbeScheduler(
        INETDNS::TimeEventSet* _timeEventSet, UDPSocket* _outSock,
        void* resolver) {
    timeEventSet = _timeEventSet;
    outSock = _outSock;

    this->resolver = resolver;
}

MDNSProbeScheduler::~MDNSProbeScheduler() {
}

std::shared_ptr<INETDNS::MDNSProbeJob> MDNSProbeScheduler::find_job(
        std::shared_ptr<INETDNS::DNSRecord> r) {
    std::shared_ptr<INETDNS::MDNSProbeJob> pj;
    for (auto it = jobs.begin(); it != jobs.end(); ++it) {
        pj = *it;

        // check if they are the same
        if (INETDNS::recordEqualNoData(pj->r, r)) {
            return pj;
        }
    }

    return NULL;
}

std::shared_ptr<INETDNS::MDNSProbeJob> MDNSProbeScheduler::find_history(
        std::shared_ptr<INETDNS::DNSRecord> r) {
    std::shared_ptr<INETDNS::MDNSProbeJob> pj;

    for (auto it = history.begin(); it != history.end(); ++it) {
        pj = *it;

        // check if they are the same
        if (INETDNS::recordEqualNoData(pj->r, r)) {
            return pj;
        }
    }

    return NULL;
}

void MDNSProbeScheduler::done(std::shared_ptr<INETDNS::MDNSProbeJob> pj) {
    pj->done = 1;
    auto it = std::find(jobs.begin(), jobs.end(), pj);
    if (it != jobs.end())
        jobs.erase(it);

    if (std::find(history.begin(), history.end(), pj) == history.end())
        return;

    history.push_back(pj);

    simtime_t now = simTime();
    pj->delivery = now;

    // update the time event

    // add random deferral value between 20 and 120
    int defer = intrand(100) + 20;
    // create simtime value from random deferral value
    std::string stime = std::to_string(defer) + std::string("ms");
    simtime_t tv = STR_SIMTIME(stime.c_str());

    timeEventSet->updateTimeEvent(pj->e, now + tv);
}

std::shared_ptr<INETDNS::MDNSProbeJob> MDNSProbeScheduler::new_job(
        std::shared_ptr<INETDNS::DNSRecord> r) {
    std::shared_ptr<MDNSProbeJob> pj(new MDNSProbeJob());
    pj->id = id_count++;
    pj->done = 0;
    pj->r = INETDNS::copyDnsRecord(r);
    pj->delivery = 0;
    // append the job to the list
    jobs.push_back(pj);

    return pj;
}

void MDNSProbeScheduler::remove_job(std::shared_ptr<INETDNS::MDNSProbeJob> pj) {
    timeEventSet->removeTimeEvent(pj->e);
    auto it = std::find(jobs.begin(), jobs.end(), pj);
    if (it != jobs.end()) {
        jobs.erase(it);
        freeDnsRecord(pj->r);
        return;
    }

    it = std::find(history.begin(), history.end(), pj);
    if (it != history.end()) {
        history.erase(it);
        freeDnsRecord(pj->r);
        return;
    }

    // no ref found? i.e. just delete ...
    freeDnsRecord(pj->r);
    pj.reset();
}

int MDNSProbeScheduler::preparePacketAndSend(std::list<std::shared_ptr<DNSQuestion>> qlist,
        std::list<std::shared_ptr<DNSRecord>> nslist, int qdcount, int nscount, int packetSize,
        int TC, int is_private) {
    int i = 0;
    std::string msgname;
    if (!is_private)
        msgname = "MDNS_probe#";
    else
        msgname = "PRIVATE_probe#";

    msgname += std::to_string(id_count);

    DNSPacket* p = INETDNS::createNQuery(msgname, qdcount, 0, nscount, 0,
            id_count++, 0);

    // append questions
    for (auto it : qlist) {
        INETDNS::appendQuestion(p, it, i);
        i++;
    }

    // append auth if available
    if (nscount > 0) {
        i = 0;
        for (auto it : nslist) {
            INETDNS::appendAuthority(p, it, i);
            i++;
        }
    }

    std::unordered_map<std::string, int> signalPars;
    signalPars["signal_type"] = 0;

    // packet fully initialized, send it via multicast

    p->setByteLength(INETDNS::estimateDnsPacketSize(p));
#ifdef DEBUG_ENABLED
    p->addPar("prettyContent");
    p->par("prettyContent") = INETDNS::dnsPacketToString(p).c_str();
#endif

    if (!is_private) {
        const char* dstr = "i=msg/bcast,red";
        p->setDisplayString(dstr);
        p->addPar("private");
        p->par("private") = false;
        signalPars["privacy"] = 0;
        signalReceiver->receiveSignal(signalPars, p);

        outSock->sendTo(p, multicast_address, MDNS_PORT);
    } else {
        const char* dstr = "i=msg/packet,green";
        p->setDisplayString(dstr);
        std::string service_type = INETDNS::extract_stype(
                p->getQuestions(0).qname);
        std::shared_ptr<INETDNS::PrivateMDNSService> psrv =
                (*private_service_table)[service_type];
        // go through the offered_to list
        p->addPar("private");
        p->par("private") = true;
        signalPars["privacy"] = 1;
        signalReceiver->receiveSignal(signalPars, p);

        for (auto it : psrv->offered_to) {
            std::string key = it;
            std::shared_ptr<INETDNS::FriendData> fdata = (*friend_data_table)[key];
            if (fdata && fdata->online) {
                // send per TCP to the privacy socket on the given port
                privacySock->sendTo(p->dup(), fdata->address, fdata->port);
            }
        }

        delete p;
    }

    // packet is out, we're finished
    return 1;
}

int MDNSProbeScheduler::append_question(std::shared_ptr<INETDNS::MDNSProbeJob> pj,
        std::list<std::shared_ptr<DNSQuestion>>* qlist, std::list<std::shared_ptr<DNSRecord>>* nslist,
        int *packetSize, int* qdcount, int* nscount, int is_private) {
    std::shared_ptr<INETDNS::DNSQuestion> q;

    int pack_has_space = 1;

    // ANY question for probing
    q = createQuestion(pj->r->rname, DNS_TYPE_VALUE_ANY, DNS_CLASS_IN);

    int qsize = sizeof(pj->r->rname) + 4; // name length + 4 bytes for type and class

    if (*packetSize + qsize > MAX_MDNS_PACKET_SIZE) {
        return 0;
    }

    // check if record fits
    int size = 10 + sizeof(pj->r->rname) + pj->r->rdlength;

    if (*packetSize + size > MAX_MDNS_PACKET_SIZE) {
        return 0;
    }

    *packetSize += qsize + size;

    (*qdcount)++;
    (*qlist).push_back(q);
    (*nscount)++;
    (*nslist).push_back(INETDNS::copyDnsRecord(pj->r));

    done(pj);

    // now see if there are more records that match..

    std::list<std::shared_ptr<MDNSProbeJob>> done_records;
    for (auto job : jobs) {
        // check if key matches ..
        if (!INETDNS::recordEqualNoData(job->r, pj->r)) {
            // record does not match...
            continue;
        }

        // check if record fits
        size = 10 + sizeof(job->r->rname) + job->r->rdlength;

        if (*packetSize + size > MAX_MDNS_PACKET_SIZE) {
            pack_has_space = 0;
            break;
        }

        *packetSize += size;

        // append record
        (*nscount)++;
        (*nslist).push_back(INETDNS::copyDnsRecord(job->r));

        done_records.push_back(job);
    }

    // mark all PJs in the list as done
    for (auto it : done_records)
        done(it);

    return pack_has_space;
}

void MDNSProbeScheduler::elapseCallback(INETDNS::TimeEvent* e, std::shared_ptr<void> data,
        void* thispointer) {
    MDNSProbeScheduler * self = static_cast<MDNSProbeScheduler*>(thispointer);
    self->elapse(e, data);
}

void MDNSProbeScheduler::post(std::shared_ptr<INETDNS::DNSRecord> r, int immediately) {
    std::shared_ptr<MDNSProbeJob> pj;
    simtime_t tv;

    if ((pj = find_history(r)))
        return; // still got a record in the history for this probe

    if (!immediately) {
        int defer = MDNS_PROBE_WAIT;
        // add random delay..
        defer += intrand(50);
        // create simtime value from random deferral value
        std::string stime = std::to_string(defer) + std::string("ms");
        tv = simTime() + STR_SIMTIME(stime.c_str());

    } else {
        tv = simTime();
    }

    if ((pj = find_job(r))) {
        if (tv < pj->delivery) {
            pj->delivery = tv;
            timeEventSet->updateTimeEvent(pj->e, tv);
        }
    } else {
        // create new job..
        pj = new_job(r);
        pj->delivery = tv;

        INETDNS::TimeEvent* e = new INETDNS::TimeEvent(this);
        e->setData(pj);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(INETDNS::MDNSProbeScheduler::elapseCallback);

        pj->e = e;
        timeEventSet->addTimeEvent(e);
    }

    std::shared_ptr<SimTime> tv_ptr(new SimTime(tv));

    callback(tv_ptr, resolver);
}

void MDNSProbeScheduler::elapse(INETDNS::TimeEvent* e, std::shared_ptr<void> data) {
    // elapse callback, cast probejob
    std::shared_ptr<MDNSProbeJob> pj = std::static_pointer_cast<MDNSProbeJob>(data);
    int is_private = 0;
    std::shared_ptr<INETDNS::PrivateMDNSService> psrv;

    if (pj->done) {
        remove_job(pj);
        return;
    }

    if (hasPrivacy) {
        // check whether the record is of private nature
        std::string service_type = INETDNS::extract_stype(pj->r->rname);
        if (private_service_table->find(service_type) != private_service_table->end()) {
            psrv = (*private_service_table)[service_type];
            is_private = psrv->is_private;
        }
    }

    int packetSize = 12; // initial header size

    std::list<std::shared_ptr<DNSQuestion>> qlist;
    std::list<std::shared_ptr<DNSRecord>> nslist;

    int qdcount = 0;
    int nscount = 0;

    int success = append_question(pj, &qlist, &nslist, &packetSize, &qdcount,
            &nscount, is_private);

    // now try to append more questions if we didn't already exceed the packet size.
    // take another query job from the list..

    std::list<std::shared_ptr<MDNSProbeJob>> list_cpy;
    list_cpy.insert(list_cpy.end(), jobs.begin(), jobs.end());
    if (!is_private) { // only do so if the job was not private, we already appended all matching keys
        for (auto job : list_cpy) {
            if(!success) break;

            int _private_job = 0;
            std::string service_type = INETDNS::extract_stype(job->r->rname);

            // check whether this service is private, do not append it if it is
            if (hasPrivacy && private_service_table->find(service_type) != private_service_table->end()) {
                psrv = (*private_service_table)[service_type];
                _private_job = psrv->is_private;
                // reschedule
                timeEventSet->updateTimeEvent(job->e,
                        simTime() + STR_SIMTIME("20ms"));

            }

            if (!_private_job) {
                success = append_question(job, &qlist, &nslist, &packetSize,
                        &qdcount, &nscount, is_private);
            }

            if (success && !_private_job) {
                done(job);
            }
        }
    }

    if (preparePacketAndSend(qlist, nslist, qdcount, nscount, packetSize,
            !success, is_private)) {
        // success, delegate?
    } else {
        // some error message?
    }

}

} /* namespace ODnsExtension */
