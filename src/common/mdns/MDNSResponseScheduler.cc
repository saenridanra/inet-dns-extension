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
#include <MDNSResponseScheduler.h>

namespace INETDNS {

MDNSResponseScheduler::MDNSResponseScheduler(TimeEventSet* _timeEventSet,
        UDPSocket* _outSock, void* resolver) {
    timeEventSet = _timeEventSet;
    outSock = _outSock;
    this->resolver = resolver;
}

MDNSResponseScheduler::~MDNSResponseScheduler() {
    // TODO Auto-generated destructor stub
}

std::shared_ptr<MDNSResponseJob> MDNSResponseScheduler::new_job(
        std::shared_ptr<DNSRecord> r, int done, int suppress) {
    std::shared_ptr<MDNSResponseJob> rj(new MDNSResponseJob());
    rj->id = id_count++;
    rj->done = done;
    rj->suppressed = suppress;
    rj->r = copyDnsRecord(r);
    rj->delivery = 0;
    rj->flush_cache = 0;
    // append the job to the list
    if (!suppress) {
        if (!done) {
            jobs.push_back(rj);
        } else {
            history.push_back(rj);
        }
    } else {
        suppressed.push_back(rj);
    }

    return rj;

}

std::shared_ptr<MDNSResponseJob> MDNSResponseScheduler::find_job(
        std::shared_ptr<DNSRecord> r) {
    std::shared_ptr<MDNSResponseJob> rj;
    for (auto it = jobs.begin(); it != jobs.end(); ++it) {
        rj = *it;
        // TODO: check half TTL lifetime before doing this!
        if (recordEqualNoData(r, rj->r)) {
            return rj;
        }
    }

    return NULL;
}

std::shared_ptr<MDNSResponseJob> MDNSResponseScheduler::find_history(
        std::shared_ptr<DNSRecord> r) {
    std::shared_ptr<MDNSResponseJob> rj;
    for (auto it = history.begin(); it != history.end(); ++it) {
        rj = *it;

        // check if they are the same
        if (recordEqualNoData(r, rj->r)) {
            if ((simTime().inUnit(-3) - rj->delivery.inUnit(-3))
                    > MDNS_RESPONSE_WAIT) {
                remove_job(rj);
                return NULL;
            }

            return rj;
        }
    }

    return NULL;
}

std::shared_ptr<MDNSResponseJob> MDNSResponseScheduler::find_suppressed(
        std::shared_ptr<DNSRecord> r, IPvXAddress* querier) {
    std::shared_ptr<MDNSResponseJob> rj;
    for (auto it = suppressed.begin(); it != suppressed.end(); ++it) {
        rj = *it;
        if (rj->suppressed) {
            continue;
        }

        // check if they are the same
        if (recordEqualNoData(r, rj->r)
                && rj->querier->str().compare(querier->str()) == 0) {
            if ((simTime().inUnit(-3) - rj->delivery.inUnit(-3))
                    > MDNS_RESPONSE_WAIT) {
                remove_job(rj);
                return std::shared_ptr<MDNSResponseJob>();
            }

            return rj;
        }
    }

    return NULL;
}

void MDNSResponseScheduler::done(std::shared_ptr<MDNSResponseJob> rj) {

    if (rj->suppressed || rj->done)
        remove_job(rj);

    rj->done = 1;
    auto it = std::find(jobs.begin(), jobs.end(), rj);
    if (it != jobs.end()) {
        jobs.erase(it);
    }
    history.push_back(rj);
    simtime_t now = simTime();
    rj->delivery = now;

    // create simtime value from random deferral value
    std::string stime = std::to_string(MDNS_RESPONSE_WAIT) + std::string("ms");
    simtime_t tv = STR_SIMTIME(stime.c_str());

    // update timeevent
    timeEventSet->updateTimeEvent(rj->e, now + tv);
}

void MDNSResponseScheduler::remove_job(std::shared_ptr<MDNSResponseJob> rj) {
    timeEventSet->removeTimeEvent(rj->e);

    if (rj->done) {
        auto it = std::find(history.begin(), history.end(), rj);
        if (it != history.end()) {
            it = history.erase(it);
            freeDnsRecord(rj->r);
        }
        return;
    } else if (rj->suppressed) {
        auto it = std::find(suppressed.begin(), suppressed.end(), rj);
        if (it != suppressed.end()) {
            it = suppressed.erase(it);
            freeDnsRecord(rj->r);
        }
        return;
    } else {
        auto it = std::find(jobs.begin(), jobs.end(), rj);
        if (it != jobs.end()) {
            it = jobs.erase(it);
            freeDnsRecord(rj->r);
        }
        return;
    }

// no ref found? i.e. just delete ...
    freeDnsRecord(rj->r);
    rj.reset();
}

void MDNSResponseScheduler::suppress(std::shared_ptr<DNSRecord> r,
        int flush_cache, IPvXAddress* querier, int immediately) {
    std::shared_ptr<MDNSResponseJob> rj;
    simtime_t now;
    simtime_t tv;
    std::string stime = std::to_string(MDNS_RESPONSE_WAIT) + std::string("ms");

    if ((rj = find_job(r))) {
        // check whether it's for the same querier
        if (rj->querier->str().compare(querier->str()) == 0
                && r->ttl >= rj->r->ttl / 2
                && isGoodbye(r) == isGoodbye(rj->r)) {
            // in this case someone knows the answer to this question already and has a valid ttl, therefore we can drop it
            remove_job(rj);
        }
    }

    if ((rj = find_suppressed(r, querier))) {
        freeDnsRecord(rj->r);
        rj->r = copyDnsRecord(r);

        // update time
        now = simTime();
        rj->delivery = now;

        tv = STR_SIMTIME(stime.c_str());
        timeEventSet->updateTimeEvent(rj->e, now + tv);

    } else {
        rj = new_job(r, 0, 1);
        rj->querier = querier;

        // set time
        now = simTime();
        rj->delivery = now;

        tv = STR_SIMTIME(stime.c_str());

        TimeEvent* e = new TimeEvent(this);
        e->setData(rj);
        e->setExpiry(now + tv);
        e->setLastRun(0);
        e->setCallback(MDNSResponseScheduler::elapseCallback);
    }
}

int MDNSResponseScheduler::appendTransitiveEntries(std::shared_ptr<DNSRecord> r,
        std::list<std::shared_ptr<DNSRecord>> *anlist, int* packetSize,
        int* ancount) {
// here we check our auth cache for transitive answers..
    int success = 1;
    if (r->rclass == DNS_CLASS_IN) {
        std::string hash;

        if (r->rtype == DNS_TYPE_VALUE_PTR) {
            hash = r->strdata + std::string(":") + std::string(DNS_TYPE_STR_SRV)
                    + std::string(":") + std::string(DNS_CLASS_STR_IN); // SRV hash;
            success = appendFromCache(hash, anlist, packetSize, ancount);

            if (success) {
                hash = r->strdata + std::string(":")
                        + std::string(DNS_TYPE_STR_TXT) + std::string(":")
                        + std::string(DNS_CLASS_STR_IN);
                success = appendFromCache(hash, anlist, packetSize, ancount);
            }

        } else if (r->rtype == DNS_TYPE_VALUE_SRV) {
            std::shared_ptr<INETDNS::SRVData> srv =
                    std::static_pointer_cast < INETDNS::SRVData
                            > (r->rdata);
            hash = srv->target + std::string(":")
                    + std::string(DNS_TYPE_STR_A) + std::string(":")
                    + std::string(DNS_CLASS_STR_IN);
            success = appendFromCache(hash, anlist, packetSize, ancount);

            if (success) {
                hash = srv->target + std::string(":")
                        + std::string(DNS_TYPE_STR_AAAA) + std::string(":")
                        + std::string(DNS_CLASS_STR_IN);
                success = appendFromCache(hash, anlist, packetSize, ancount);
            }
        } else if (r->rtype == DNS_TYPE_VALUE_CNAME) {
            // For our test purposes we only check CNAMES for A, AAAA, SRV, PTR, TXT..
            hash = r->strdata + std::string(":") + std::string(DNS_TYPE_STR_A)
                    + std::string(":") + std::string(DNS_CLASS_STR_IN);
            success = appendFromCache(hash, anlist, packetSize, ancount);

            if (success) {
                hash = r->strdata + std::string(":")
                        + std::string(DNS_TYPE_STR_AAAA) + std::string(":")
                        + std::string(DNS_CLASS_STR_IN);
                success = appendFromCache(hash, anlist, packetSize, ancount);
            }

            if (success) {
                hash = r->strdata + std::string(":")
                        + std::string(DNS_TYPE_STR_PTR) + std::string(":")
                        + std::string(DNS_CLASS_STR_IN); // PTR hash;
                success = appendFromCache(hash, anlist, packetSize, ancount);
            }

            if (success) {
                hash = r->strdata + std::string(":")
                        + std::string(DNS_TYPE_STR_SRV) + std::string(":")
                        + std::string(DNS_CLASS_STR_IN); // SRV hash;
                success = appendFromCache(hash, anlist, packetSize, ancount);
            }

            if (success) {
                hash = r->strdata + std::string(":")
                        + std::string(DNS_TYPE_STR_TXT) + std::string(":")
                        + std::string(DNS_CLASS_STR_IN);
                success = appendFromCache(hash, anlist, packetSize, ancount);
            }
        }

    }

    return success;

}

int MDNSResponseScheduler::appendFromCache(std::string hash,
        std::list<std::shared_ptr<DNSRecord>> *anlist, int* packetSize,
        int* ancount) {
    std::list<std::shared_ptr<DNSRecord>> cache_entries;
    std::shared_ptr<DNSRecord> from_cache;
    cache_entries = auth_cache->get_from_cache(hash);

    // for each cache entry, call append record..
    for (auto from_cache : cache_entries) {
        int size = 10 + sizeof(from_cache->rname) + from_cache->rdlength;

        if (from_cache->rtype == DNS_TYPE_VALUE_SRV)
            size += 6; // since we do not have WEIGHT, PRIO and PORT in the SRV
                       // record, we add these 6 bytes.

        if (*packetSize + size > MAX_MDNS_PACKET_SIZE) {
            return 0;
        }

        *packetSize += size;

        appendRecord(from_cache, anlist, packetSize, ancount);
        (*ancount)++;
    }
    return 1;
}

int MDNSResponseScheduler::appendRecord(std::shared_ptr<DNSRecord> r,
        std::list<std::shared_ptr<DNSRecord>> *anlist, int* packetSize,
        int* ancount) {

    int size = 10 + sizeof(r->rname) + r->rdlength;

    if (*packetSize + size > MAX_MDNS_PACKET_SIZE) {
        return 0;
    }

    *packetSize += size;

    // append record to answer list
    anlist->push_back(copyDnsRecord(r));
    (*ancount)++;

    return appendTransitiveEntries(r, anlist, packetSize, ancount);
}

int MDNSResponseScheduler::preparePacketAndSend(
        std::list<std::shared_ptr<DNSRecord>> anlist, int ancount,
        int packetSize, int is_private) {

    std::string msgname;
    if (!is_private)
        msgname = "MDNS_response#";
    else
        msgname = "PRIVATE_response#";

    msgname += std::to_string(id_count);

    DNSPacket* p = createResponse(msgname, 0, ancount, 0, 0, id_count, 0, 1, 0,
            0, 0);

// append answers if available
    int i = 0;
// append questions
    if (ancount > 0) {
        for (auto it = anlist.begin(); it != anlist.end(); ++it) {
            appendAnswer(p, *it, i);
            i++;
        }
    }

    std::unordered_map<std::string, int> signalPars;
    signalPars["signal_type"] = 2;

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
        std::string service_type = extract_stype(p->getAnswers(0).rname);
        std::shared_ptr<PrivateMDNSService> psrv =
                (*private_service_table)[service_type];
        // go through the offered_to list

        p->addPar("private");
        p->par("private") = true;
        signalPars["privacy"] = 1;
        signalReceiver->receiveSignal(signalPars, p);

        for (auto key : psrv->offered_to) {
            std::shared_ptr<FriendData> fdata = (*friend_data_table)[key];
            if (fdata && fdata->online) {
                // send per TCP to the privacy socket on the given port
                privacySock->sendTo(p->dup(), fdata->address, fdata->port);
            }
        }
        delete p;
    }

    return 1;
}

void MDNSResponseScheduler::post(std::shared_ptr<DNSRecord> r, int flush_cache,
        IPvXAddress* querier, int immediately) {
    std::shared_ptr<MDNSResponseJob> rj;
    simtime_t tv;
    std::string stime = std::to_string(MDNS_RESPONSE_WAIT + intrand(50)) + std::string("ms"); // add random delay.

    if ((rj = find_suppressed(r, querier)) && rj->r->ttl >= r->ttl / 2
            && isGoodbye(r) == isGoodbye(rj->r)) {
        // response exists and is suppressed..
        return;
    }

    if ((rj = find_history(r))) { // response in history?
        if ((rj->flush_cache || !flush_cache) && rj->r->ttl >= r->ttl / 2
                && isGoodbye(r) == isGoodbye(rj->r)) {
            return;
        }

        remove_job(rj); // outdated
    }

    if ((rj = find_job(r))) {
        tv = simTime() + STR_SIMTIME(stime.c_str());

        if (tv < rj->delivery) {
            rj->delivery = tv;
            timeEventSet->updateTimeEvent(rj->e, tv);
        }

        rj->flush_cache = flush_cache;
        rj->querier = querier;

        freeDnsRecord(rj->r);
        rj->r = copyDnsRecord(r);
        return;

    } else {
        tv = simTime() + STR_SIMTIME(stime.c_str());

        rj = new_job(r, 0, 0);
        rj->delivery = tv;
        rj->flush_cache = flush_cache;

        TimeEvent* e = new TimeEvent(this);
        e->setData(rj);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(MDNSResponseScheduler::elapseCallback);

        rj->e = e;
        timeEventSet->addTimeEvent(e);
        if (querier) {
            rj->querier = querier;
        }
    }

    std::shared_ptr<simtime_t> tv_ptr(new SimTime(tv));

    callback(tv_ptr, resolver);

}

void MDNSResponseScheduler::check_dup(std::shared_ptr<DNSRecord> r,
        int flush_cache) {
    std::shared_ptr<MDNSResponseJob> rj;
    simtime_t now;
    simtime_t tv;
    std::string stime = std::to_string(MDNS_RESPONSE_WAIT) + std::string("ms");

    if ((rj = find_job(r))) {
        // check whether it's for the same querier
        if ((!rj->flush_cache || flush_cache) && r->ttl >= rj->r->ttl / 2
                && isGoodbye(r) == isGoodbye(rj->r)) {
            done(rj);
        }
        return;
    }

    if ((rj = find_history(r))) {
        freeDnsRecord(rj->r);
        rj->r = copyDnsRecord(r);

        // update time
        now = simTime();
        rj->delivery = now;

        tv = STR_SIMTIME(stime.c_str());

        timeEventSet->updateTimeEvent(rj->e, now + tv);
    } else {
        rj = new_job(r, 1, 0);
        rj->querier = NULL;

        // set time
        now = simTime();
        rj->delivery = now;

        tv = STR_SIMTIME(stime.c_str());

        TimeEvent* e = new TimeEvent(this);
        e->setData(rj);
        e->setExpiry(now + tv);
        e->setLastRun(0);
        e->setCallback(MDNSResponseScheduler::elapseCallback);
        rj->e = e;

        timeEventSet->addTimeEvent(e);
    }

    rj->flush_cache = flush_cache;
}

void MDNSResponseScheduler::elapse(TimeEvent* e, std::shared_ptr<void> data) {
    std::shared_ptr<MDNSResponseJob> rj = std::static_pointer_cast
            < MDNSResponseJob > (data);
    int packetSize = 12; // initial header size
    int ancount = 0;
    std::list<std::shared_ptr<DNSRecord>> anlist;
    int is_private = 0;

    if (rj->done || rj->suppressed) {
        remove_job(rj);
        return;
    }

    std::string service_type;
    if (hasPrivacy) {
        // check whether the record is of private nature
        service_type = extract_stype(rj->r->rname);
        if (private_service_table->find(service_type)
                != private_service_table->end()) {
            std::shared_ptr<PrivateMDNSService> psrv =
                    (*private_service_table)[service_type];
            is_private = psrv->is_private;
        }
    }

    int success = appendRecord(rj->r, &anlist, &packetSize, &ancount);
    done(rj);

    std::list<std::shared_ptr<MDNSResponseJob>> done_records;

    if (!is_private) {
        for (auto job : jobs) {
            if(!success) break;

            int _private_job = 0;
            service_type = extract_stype(job->r->rname);

            // check whether this service is private, do not append it if it is
            if (hasPrivacy
                    && private_service_table->find(service_type)
                            != private_service_table->end()) {
                std::shared_ptr<PrivateMDNSService> psrv =
                        (*private_service_table)[service_type];
                _private_job = psrv->is_private;
                // reschedule
                timeEventSet->updateTimeEvent(job->e,
                        simTime() + STR_SIMTIME("20ms"));
            }

            if (!_private_job) {
                success = appendRecord(job->r, &anlist, &packetSize, &ancount);
            }

            if (success && !_private_job) {
                done_records.push_back(job);
            }
        }
    } else {
        // append records with matching service_type!
        for (auto job : jobs) {
            if(!success) break;

            std::string job_stype = extract_stype(job->r->rname);
            // append if it is not the same job
            int not_equal = service_type.compare(job_stype)
                    && recordDataEqual(job->r, rj->r);
            if (not_equal) {
                success = appendRecord(job->r, &anlist, &packetSize, &ancount);
            }

            if (not_equal && success) {
                done_records.push_back(job);
            }
        }
    }

    for(auto job : done_records) done(job);

    if (ancount == 0) {
        return;
    }

    if (!preparePacketAndSend(anlist, ancount, packetSize, is_private)) {

    }

}

void MDNSResponseScheduler::elapseCallback(TimeEvent* e,
        std::shared_ptr<void> data, void* thispointer) {
    MDNSResponseScheduler * self =
            static_cast<MDNSResponseScheduler*>(thispointer);
    self->elapse(e, data);
}

} /* namespace ODnsExtension */
