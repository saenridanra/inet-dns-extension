/* Copyright (c) 2014 Andreas Rain

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
#include <mdns/MDNSResponseScheduler.h>

namespace ODnsExtension {

MDNSResponseScheduler::MDNSResponseScheduler(
        ODnsExtension::TimeEventSet* _timeEventSet, UDPSocket* _outSock,
        void* resolver) {
    timeEventSet = _timeEventSet;
    outSock = _outSock;
    history = NULL;
    jobs = NULL;
    suppressed = NULL;
    this->resolver = resolver;
}

MDNSResponseScheduler::~MDNSResponseScheduler() {
    // TODO Auto-generated destructor stub
}

ODnsExtension::MDNSResponseJob* MDNSResponseScheduler::new_job(
        ODnsExtension::DNSRecord* r, int done, int suppress) {
    MDNSResponseJob* rj = (MDNSResponseJob*) (malloc(sizeof(*rj)));
    rj->id = id_count++;
    rj->done = done;
    rj->suppressed = suppress;
    rj->r = ODnsExtension::copyDnsRecord(r);
    rj->delivery = 0;
    rj->flush_cache = 0;
    // append the job to the list
    if (!suppress) {
        if (!done) {
            jobs = g_list_append(jobs, rj);
        } else {
            history = g_list_append(history, rj);
        }
    } else {
        suppressed = g_list_append(suppressed, rj);
    }

    return rj;

}

ODnsExtension::MDNSResponseJob* MDNSResponseScheduler::find_job(
        ODnsExtension::DNSRecord* r) {
    ODnsExtension::MDNSResponseJob* rj;
    GList* next = g_list_first(jobs);

    while (next) {
        rj = (ODnsExtension::MDNSResponseJob*) next->data;

        // check if they are the same
        int comp = !g_strcmp0(rj->r->rname, r->rname)
                && rj->r->rtype == r->rtype && rj->r->rclass == r->rclass;

        // TODO: check half TTL lifetime before doing this!

        if (comp) {
            return rj;
        }

        next = g_list_next(next);
    }

    return NULL;
}

ODnsExtension::MDNSResponseJob* MDNSResponseScheduler::find_history(
        ODnsExtension::DNSRecord* r) {
    ODnsExtension::MDNSResponseJob* rj;
    GList* next = g_list_first(history);

    while (next) {
        rj = (ODnsExtension::MDNSResponseJob*) next->data;

        // check if they are the same
        int comp = !g_strcmp0(rj->r->rname, r->rname)
                && rj->r->rtype == r->rtype && rj->r->rclass == r->rclass;

        if (comp) {
            if ((simTime().inUnit(-3) - rj->delivery.inUnit(-3))
                    > MDNS_RESPONSE_WAIT) {
                remove_job(rj);
                return NULL;
            }

            return rj;
        }

        next = g_list_next(next);
    }

    return NULL;
}

ODnsExtension::MDNSResponseJob* MDNSResponseScheduler::find_suppressed(
        ODnsExtension::DNSRecord* r, IPvXAddress* querier) {
    ODnsExtension::MDNSResponseJob* rj;
    GList* next = g_list_first(suppressed);

    while (next) {
        rj = (ODnsExtension::MDNSResponseJob*) next->data;
        if (rj->suppressed) {

            next = g_list_next(next);
            continue;
        }

        // check if they are the same
        int comp = !g_strcmp0(rj->r->rname, r->rname)
                && rj->r->rtype == r->rtype && rj->r->rclass == r->rclass
                && !g_strcmp0(rj->querier->str().c_str(),
                        querier->str().c_str());

        if (comp) {
            if ((simTime().inUnit(-3) - rj->delivery.inUnit(-3))
                    > MDNS_RESPONSE_WAIT) {
                remove_job(rj);
                return NULL;
            }

            return rj;
        }

        next = g_list_next(next);
    }

    return NULL;
}

void MDNSResponseScheduler::done(ODnsExtension::MDNSResponseJob* rj) {

    if (rj->suppressed || rj->done)
        remove_job(rj);

    rj->done = 1;
    jobs = g_list_remove(jobs, rj);
    history = g_list_append(history, rj);
    simtime_t now = simTime();
    rj->delivery = now;

    // update the time event

    // create simtime value from random deferral value
    char* stime = g_strdup_printf("%dms", MDNS_RESPONSE_WAIT);
    simtime_t tv = STR_SIMTIME(stime);
    g_free(stime);

    timeEventSet->updateTimeEvent(rj->e, now + tv);
}

void MDNSResponseScheduler::remove_job(ODnsExtension::MDNSResponseJob* rj) {
    timeEventSet->removeTimeEvent(rj->e);

    if (rj->done) {
        history = g_list_remove(history, rj);
        freeDnsRecord(rj->r);
        g_free(rj);
        return;
    } else if (rj->suppressed) {
        suppressed = g_list_remove(suppressed, rj);
        freeDnsRecord(rj->r);
        g_free(rj);
        return;
    } else {
        jobs = g_list_remove(jobs, rj);
        freeDnsRecord(rj->r);
        g_free(rj);
        return;
    }

    // no ref found? i.e. just delete ...
    freeDnsRecord(rj->r);
    g_free(rj);
}

void MDNSResponseScheduler::suppress(ODnsExtension::DNSRecord* r,
        int flush_cache, IPvXAddress* querier, int immediately) {
    MDNSResponseJob* rj;
    simtime_t now;
    simtime_t tv;
    char* stime;

    if ((rj = find_job(r))) {
        // check whether it's for the same querier
        if (!g_strcmp0(rj->querier->str().c_str(), querier->str().c_str())
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

        stime = g_strdup_printf("%dms", MDNS_RESPONSE_WAIT);
        tv = STR_SIMTIME(stime);
        g_free(stime);

        timeEventSet->updateTimeEvent(rj->e, now + tv);

    } else {
        rj = new_job(r, 0, 1);
        rj->querier = querier;

        // set time
        now = simTime();
        rj->delivery = now;

        stime = g_strdup_printf("%dms", MDNS_RESPONSE_WAIT);
        tv = STR_SIMTIME(stime);
        g_free(stime);

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(rj);
        e->setExpiry(now + tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSResponseScheduler::elapseCallback);
    }
}

int MDNSResponseScheduler::appendTransitiveEntries(ODnsExtension::DNSRecord* r,
        GList** anlist, int* packetSize, int* ancount) {
    // here we check our auth cache for transitive answers..
    int success = 1;
    if (r->rclass == DNS_CLASS_IN) {
        char* hash;

        if (r->rtype == DNS_TYPE_VALUE_PTR) {
            hash = g_strdup_printf("%s:%s:%s", r->rdata, DNS_TYPE_STR_SRV,
            DNS_CLASS_STR_IN); // SRV hash;
            success = appendFromCache(hash, anlist, packetSize, ancount);
            g_free(hash);

            if (success) {
                hash = g_strdup_printf("%s:%s:%s", r->rdata, DNS_TYPE_STR_TXT,
                DNS_CLASS_STR_IN); // TXT hash;
                success = appendFromCache(hash, anlist, packetSize, ancount);
                g_free(hash);
            }

        } else if (r->rtype == DNS_TYPE_VALUE_SRV) {
            hash = g_strdup_printf("%s:%s:%s", r->rdata, DNS_TYPE_STR_A,
            DNS_CLASS_STR_IN); // A hash;
            success = appendFromCache(hash, anlist, packetSize, ancount);
            g_free(hash);

            if (success) {
                hash = g_strdup_printf("%s:%s:%s", r->rdata, DNS_TYPE_STR_AAAA,
                DNS_CLASS_STR_IN); // AAAA hash;
                success = appendFromCache(hash, anlist, packetSize, ancount);
                g_free(hash);
            }
        } else if (r->rtype == DNS_TYPE_VALUE_CNAME) {
            // For our test purposes we only check CNAMES for A, AAAA, SRV, PTR, TXT..
            hash = g_strdup_printf("%s:%s:%s", r->rdata, DNS_TYPE_STR_A,
            DNS_CLASS_STR_IN); // A hash;
            success = appendFromCache(hash, anlist, packetSize, ancount);
            g_free(hash);

            if (success) {
                hash = g_strdup_printf("%s:%s:%s", r->rdata, DNS_TYPE_STR_AAAA,
                DNS_CLASS_STR_IN); // AAAA hash;
                success = appendFromCache(hash, anlist, packetSize, ancount);
                g_free(hash);
            }

            if (success) {
                hash = g_strdup_printf("%s:%s:%s", r->rdata, DNS_TYPE_STR_PTR,
                DNS_CLASS_STR_IN); // PTR hash;
                success = appendFromCache(hash, anlist, packetSize, ancount);
                g_free(hash);
            }

            if (success) {
                hash = g_strdup_printf("%s:%s:%s", r->rdata, DNS_TYPE_STR_SRV,
                DNS_CLASS_STR_IN); // SRV hash;
                success = appendFromCache(hash, anlist, packetSize, ancount);
                g_free(hash);
            }

            if (success) {
                hash = g_strdup_printf("%s:%s:%s", r->rdata, DNS_TYPE_STR_TXT,
                DNS_CLASS_STR_IN); // TXT hash;
                success = appendFromCache(hash, anlist, packetSize, ancount);
                g_free(hash);
            }
        }

    }

    return success;

}

int MDNSResponseScheduler::appendFromCache(char* hash, GList** anlist,
        int* packetSize, int* ancount) {
    GList* cache_entries;
    DNSTimeRecord* from_cache;
    cache_entries = auth_cache->get_from_cache(hash);

    // for each cache entry, call append record..
    while (cache_entries) {
        from_cache = (DNSTimeRecord*) cache_entries->data;

        int size = 10 + sizeof(from_cache->record->rname)
                + from_cache->record->rdlength;

        if (from_cache->record->rtype == DNS_TYPE_VALUE_SRV)
            size += 6; // since we do not have WEIGHT, PRIO and PORT in the SRV
                       // record, we add these 6 bytes.

        if (*packetSize + size > MAX_MDNS_PACKET_SIZE) {
            return 0;
        }

        *packetSize += size;

        appendRecord(from_cache->record, anlist, packetSize, ancount);
        (*ancount)++;
    }
    return 1;
}

int MDNSResponseScheduler::appendRecord(ODnsExtension::DNSRecord* r,
        GList** anlist, int* packetSize, int* ancount) {

    int size = 10 + sizeof(r->rname) + r->rdlength;

    if (*packetSize + size > MAX_MDNS_PACKET_SIZE) {
        return 0;
    }

    *packetSize += size;

    // append record to answer list
    *anlist = g_list_append(*anlist, ODnsExtension::copyDnsRecord(r));
    (*ancount)++;

    return appendTransitiveEntries(r, anlist, packetSize, ancount);
}

int MDNSResponseScheduler::preparePacketAndSend(GList* anlist, int ancount,
        int packetSize, int is_private) {
    char* msgname = g_strdup_printf("mdns_response#%d", id_count);
    DNSPacket* p = ODnsExtension::createResponse(msgname, 0, ancount, 0, 0,
            id_count, 0, 1, 0, 0, 0);

    // append answers if available
    int i = 0;
    // append questions
    GList* next = g_list_first(anlist);
    if (ancount > 0) {
        while (next) {
            ODnsExtension::appendAnswer(p, (DNSRecord*) next->data, i);
            i++;
            next = g_list_next(next);
        }
    }

    p->setByteLength(packetSize);
    if (!is_private) {
        outSock->sendTo(p, multicast_address, MDNS_PORT);
    } else {
        char* service_type = ODnsExtension::extract_stype(
                p->getAnswers(0).rname);
        ODnsExtension::PrivateMDNSService* psrv =
                (ODnsExtension::PrivateMDNSService*) g_hash_table_lookup(
                        private_service_table, service_type);
        // go through the offered_to list
        next = g_list_first(psrv->offered_to);

        while (next) {
            char* key = (char*) next->data;
            ODnsExtension::FriendData* fdata =
                    (ODnsExtension::FriendData*) g_hash_table_lookup(
                            friend_data_table, key);
            if (fdata && fdata->online) {
                // send per TCP to the privacy socket on the given port
                privacySock->sendTo(p->dup(), fdata->address, fdata->port);
            }
            next = g_list_next(next);
        }
        delete p;
    }

    return 1;
}

void MDNSResponseScheduler::post(ODnsExtension::DNSRecord* r, int flush_cache,
        IPvXAddress* querier, int immediately) {
    MDNSResponseJob* rj;
    simtime_t tv;
    char* stime;

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
        stime = g_strdup_printf("%dms", MDNS_RESPONSE_WAIT);
        tv = simTime() + STR_SIMTIME(stime);
        g_free(stime);

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
        stime = g_strdup_printf("%dms", MDNS_RESPONSE_WAIT);
        tv = simTime() + STR_SIMTIME(stime);
        g_free(stime);

        rj = new_job(r, 0, 0);
        rj->delivery = tv;
        rj->flush_cache = flush_cache;

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(rj);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSResponseScheduler::elapseCallback);

        rj->e = e;
        timeEventSet->addTimeEvent(e);
        if (querier) {
            rj->querier = querier;
        }
    }

    callback(&tv, resolver);

}

void MDNSResponseScheduler::check_dup(ODnsExtension::DNSRecord* r,
        int flush_cache) {
    MDNSResponseJob* rj;
    simtime_t now;
    simtime_t tv;
    char* stime;

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

        stime = g_strdup_printf("%dms", MDNS_RESPONSE_WAIT);
        tv = STR_SIMTIME(stime);
        g_free(stime);

        timeEventSet->updateTimeEvent(rj->e, now + tv);
    } else {
        rj = new_job(r, 1, 0);
        rj->querier = NULL;

        // set time
        now = simTime();
        rj->delivery = now;

        stime = g_strdup_printf("%dms", MDNS_RESPONSE_WAIT);
        tv = STR_SIMTIME(stime);
        g_free(stime);

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(rj);
        e->setExpiry(now + tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSResponseScheduler::elapseCallback);
        rj->e = e;

        timeEventSet->addTimeEvent(e);
    }

    rj->flush_cache = flush_cache;
}

void MDNSResponseScheduler::elapse(ODnsExtension::TimeEvent* e, void* data) {
    MDNSResponseJob* rj = (MDNSResponseJob*) data;
    int packetSize = 12; // initial header size
    int ancount = 0;
    GList* anlist = NULL;
    int is_private = 0;

    if (rj->done || rj->suppressed) {
        remove_job(rj);
        return;
    }

    if (hasPrivacy) {
        // check whether the record is of private nature
        char* service_type = ODnsExtension::extract_stype(rj->r->rname);
        if (g_hash_table_contains(private_service_table, service_type)) {
            ODnsExtension::PrivateMDNSService* psrv =
                    (ODnsExtension::PrivateMDNSService*) g_hash_table_lookup(
                            private_service_table, service_type);
            is_private = psrv->is_private;
        }
    }

    int success = appendRecord(rj->r, &anlist, &packetSize, &ancount);
    done(rj);

    if (!is_private) {
        GList* head = g_list_first(jobs);
        while (success && head) {
            MDNSResponseJob* job = (MDNSResponseJob*) head->data;

            int _private_job = 0;
            char* service_type = ODnsExtension::extract_stype(job->r->rname);

            // check whether this service is private, do not append it if it is
            if (hasPrivacy
                    && g_hash_table_contains(private_service_table,
                            service_type)) {
                ODnsExtension::PrivateMDNSService* psrv =
                        (ODnsExtension::PrivateMDNSService*) g_hash_table_lookup(
                                private_service_table, service_type);
                _private_job = psrv->is_private;
                // reschedule
                timeEventSet->updateTimeEvent(job->e, simTime() + STR_SIMTIME("20ms"));
            }

            if (!_private_job) {
                success = appendRecord(job->r, &anlist, &packetSize, &ancount);
            }

            head = g_list_next(head);

            if (success && !_private_job) {
                done(job);
            }
        }
    }

    if (ancount == 0) {
        return;
    }

    if (!preparePacketAndSend(anlist, ancount, packetSize, is_private)) {

    }

}

void MDNSResponseScheduler::elapseCallback(ODnsExtension::TimeEvent* e,
        void* data, void* thispointer) {
    MDNSResponseScheduler * self =
            static_cast<MDNSResponseScheduler*>(thispointer);
    self->elapse(e, data);
}

} /* namespace ODnsExtension */
