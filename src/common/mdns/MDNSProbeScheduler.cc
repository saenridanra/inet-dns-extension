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

namespace ODnsExtension {

MDNSProbeScheduler::MDNSProbeScheduler(
        ODnsExtension::TimeEventSet* _timeEventSet, UDPSocket* _outSock,
        void* resolver) {
    timeEventSet = _timeEventSet;
    outSock = _outSock;
    history = NULL;
    jobs = NULL;

    this->resolver = resolver;
}

MDNSProbeScheduler::~MDNSProbeScheduler() {
}

ODnsExtension::MDNSProbeJob* MDNSProbeScheduler::find_job(
        ODnsExtension::DNSRecord* r) {
    ODnsExtension::MDNSProbeJob* pj;
    GList* next = g_list_first(jobs);

    while (next) {
        pj = (ODnsExtension::MDNSProbeJob*) next->data;

        // check if they are the same
        int comp = !g_strcmp0(pj->r->rname, r->rname)
                && pj->r->rtype == r->rtype && pj->r->rclass == r->rclass;
        if (comp) {
            return pj;
        }

        next = g_list_next(next);
    }

    return NULL;
}

ODnsExtension::MDNSProbeJob* MDNSProbeScheduler::find_history(
        ODnsExtension::DNSRecord* r) {
    ODnsExtension::MDNSProbeJob* pj;
    GList* next = g_list_first(history);

    while (next) {
        pj = (ODnsExtension::MDNSProbeJob*) next->data;

        // check if they are the same
        int comp = !g_strcmp0(pj->r->rname, r->rname)
                && pj->r->rtype == r->rtype && pj->r->rclass == r->rclass;
        if (comp) {
            return pj;
        }

        next = g_list_next(next);
    }

    return NULL;
}

void MDNSProbeScheduler::done(ODnsExtension::MDNSProbeJob* pj) {
    pj->done = 1;
    jobs = g_list_remove(g_list_first(jobs), pj);
    if (!g_list_find(history, pj))
        history = g_list_append(history, pj);
    else
        return;

    simtime_t now = simTime();
    pj->delivery = now;

    // update the time event

    // add random deferral value between 20 and 120
    int defer = intrand(100) + 20;
    // create simtime value from random deferral value
    char* stime = g_strdup_printf("%dms", defer);
    simtime_t tv = STR_SIMTIME(stime);
    g_free(stime);

    timeEventSet->updateTimeEvent(pj->e, now + tv);
}

ODnsExtension::MDNSProbeJob* MDNSProbeScheduler::new_job(
        ODnsExtension::DNSRecord* r) {
    MDNSProbeJob* pj = (MDNSProbeJob*) malloc(sizeof(*pj));
    pj->id = id_count++;
    pj->done = 0;
    pj->r = ODnsExtension::copyDnsRecord(r);
    pj->delivery = 0;
    // append the job to the list
    jobs = g_list_append(jobs, pj);

    return pj;
}

void MDNSProbeScheduler::remove_job(ODnsExtension::MDNSProbeJob* pj) {
    timeEventSet->removeTimeEvent(pj->e);
    if (find_job(pj->r)) {
        GList* tmp = g_list_first(jobs);
        tmp = g_list_remove(tmp, pj);
        jobs = tmp;
        freeDnsRecord(pj->r);
        g_free(pj);
        return;
    } else if (find_history(pj->r)) {
        GList* tmp = g_list_first(history);
        tmp = g_list_remove(tmp, pj);
        history = tmp;
        freeDnsRecord(pj->r);
        g_free(pj);
        return;
    }

    // no ref found? i.e. just delete ...
    freeDnsRecord(pj->r);
    g_free(pj);
}

int MDNSProbeScheduler::preparePacketAndSend(GList* qlist, GList* nslist,
        int qdcount, int nscount, int packetSize, int TC, int is_private) {
    int i = 0;
    char* msgname;
    if(!is_private)
        msgname = g_strdup_printf("MDNS_probe#%d", id_count);
    else
        msgname = g_strdup_printf("PRIVATE_probe#%d", id_count);

    DNSPacket* p = ODnsExtension::createNQuery(msgname, qdcount, 0, nscount, 0,
            id_count++, 0);

    // append questions
    GList* next = g_list_first(qlist);
    while (next) {
        ODnsExtension::appendQuestion(p, (DNSQuestion*) next->data, i);
        i++;
        next = g_list_next(next);
    }

    // append auth if available
    if (nscount > 0) {
        i = 0;
        next = g_list_first(nslist);
        while (next) {
            ODnsExtension::appendAuthority(p, (DNSRecord*) next->data, i);
            i++;
            next = g_list_next(next);
        }
    }

    // packet fully initialized, send it via multicast
    p->setByteLength(packetSize);
    if (!is_private) {
        const char* dstr = "i=msg/bcast,red";
        p->setDisplayString(dstr);
        outSock->sendTo(p, multicast_address, MDNS_PORT);
    } else {
        const char* dstr = "i=msg/packet,green";
        p->setDisplayString(dstr);
        char* service_type = ODnsExtension::extract_stype(
                p->getQuestions(0).qname);
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

    // packet is out, we're finished
    return 1;
}

int MDNSProbeScheduler::append_question(ODnsExtension::MDNSProbeJob* pj,
        GList** qlist, GList** nslist, int *packetSize, int* qdcount,
        int* nscount, int is_private) {
    ODnsExtension::DNSQuestion* q;

    int pack_has_space = 1;
    GList* done_records = NULL;

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
    *qlist = g_list_append(*qlist, q);
    (*nscount)++;
    *nslist = g_list_append(*nslist, ODnsExtension::copyDnsRecord(pj->r));

    done(pj);

    // now see if there are more records that match..

    GList* next = g_list_first(jobs);
    while (next) {

        // Check job
        MDNSProbeJob* job = (MDNSProbeJob*) next->data;

        // check if key matches ..
        if (g_strcmp0(job->r->rname, pj->r->rname)
                || job->r->rclass != pj->r->rclass) {
            // record does not match...
            next = g_list_next(next);
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
        *nslist = g_list_append(*nslist, ODnsExtension::copyDnsRecord(job->r));

        done_records = g_list_append(done_records, job);

        next = g_list_next(next);
    }

    // mark all PJs in the list as done
    next = g_list_first(done_records);
    while (next) {
        done((MDNSProbeJob*) next->data);
        next = g_list_next(next);
    }

    return pack_has_space;
}

void MDNSProbeScheduler::elapseCallback(ODnsExtension::TimeEvent* e, void* data,
        void* thispointer) {
    MDNSProbeScheduler * self = static_cast<MDNSProbeScheduler*>(thispointer);
    self->elapse(e, data);
}

void MDNSProbeScheduler::post(ODnsExtension::DNSRecord* r, int immediately) {
    MDNSProbeJob* pj;
    simtime_t tv;

    if ((pj = find_history(r)))
        return; // still got a record in the history for this probe

    if (!immediately) {
        int defer = MDNS_PROBE_WAIT;
        // create simtime value from random deferral value
        char* stime = g_strdup_printf("%dms", defer);
        tv = simTime() + STR_SIMTIME(stime);
        g_free(stime);

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

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(pj);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSProbeScheduler::elapseCallback);

        pj->e = e;
        timeEventSet->addTimeEvent(e);
    }

    callback(&tv, resolver);
}

void MDNSProbeScheduler::elapse(ODnsExtension::TimeEvent* e, void* data) {
    // elapse callback, cast probejob
    MDNSProbeJob* pj = (MDNSProbeJob*) data;
    int is_private = 0;
    ODnsExtension::PrivateMDNSService* psrv = NULL;

    if (pj->done) {
        remove_job(pj);
        return;
    }

    if (hasPrivacy) {
        // check whether the record is of private nature
        char* service_type = ODnsExtension::extract_stype(pj->r->rname);
        if (g_hash_table_contains(private_service_table, service_type)) {
            psrv = (ODnsExtension::PrivateMDNSService*) g_hash_table_lookup(
                    private_service_table, service_type);
            is_private = psrv->is_private;
        }
    }

    int packetSize = 12; // initial header size

    GList* qlist = NULL;
    GList* nslist = NULL;

    int qdcount = 0;
    int nscount = 0;

    int success = append_question(pj, &qlist, &nslist, &packetSize, &qdcount,
            &nscount, is_private);

    // now try to append more questions if we didn't already exceed the packet size.
    // take another query job from the list..
    if (!is_private) { // only do so if the job was not private, we already appended all matching keys
        GList* head = g_list_first(jobs);
        while (success && head) {
            MDNSProbeJob* job = (MDNSProbeJob*) head->data;
            int _private_job = 0;
            char* service_type = ODnsExtension::extract_stype(job->r->rname);

            // check whether this service is private, do not append it if it is
            if (hasPrivacy
                    && g_hash_table_contains(private_service_table,
                            service_type)) {
                psrv = (ODnsExtension::PrivateMDNSService*) g_hash_table_lookup(
                        private_service_table, service_type);
                _private_job = psrv->is_private;
                // reschedule
                timeEventSet->updateTimeEvent(job->e, simTime() + STR_SIMTIME("20ms"));

            }

            if (!_private_job) {
                success = append_question(job, &qlist, &nslist, &packetSize,
                        &qdcount, &nscount, is_private);
            }

            head = g_list_next(head);
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
