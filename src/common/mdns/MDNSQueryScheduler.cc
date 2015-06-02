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

#include <mdns/MDNSQueryScheduler.h>

namespace ODnsExtension {

MDNSQueryScheduler::MDNSQueryScheduler(
        ODnsExtension::TimeEventSet* _timeEventSet, UDPSocket* _outSock,
        void* resolver) {

    timeEventSet = _timeEventSet;
    outSock = _outSock;

    this->resolver = resolver;

}

MDNSQueryScheduler::~MDNSQueryScheduler() {
    // free all lists ...
}

void MDNSQueryScheduler::elapseCallback(ODnsExtension::TimeEvent* e,
        std::shared_ptr<void> data, void* thispointer) {
    MDNSQueryScheduler * self = static_cast<MDNSQueryScheduler*>(thispointer);
    self->elapse(e, data);
}

void MDNSQueryScheduler::elapse(ODnsExtension::TimeEvent* e,
        std::shared_ptr<void> data) {
    std::shared_ptr<ODnsExtension::MDNSQueryJob> qj = std::static_pointer_cast
            < MDNSQueryJob > (data);

    if (qj->done) {
        remove_job(qj); // remove the job from history as it is done already
        return;
    }

    int is_private = 0;
    if (hasPrivacy) {
        // check whether the record is of private nature
        std::string service_type = ODnsExtension::extract_stype(qj->key->name);
        if (private_service_table->find(service_type)
                != private_service_table->end()) {
            std::shared_ptr<ODnsExtension::PrivateMDNSService> psrv =
                    (*private_service_table)[service_type];
            is_private = psrv->is_private;
        }
    }

    int packetSize = 12; // initial header size

    std::list<std::shared_ptr<DNSQuestion>> qlist;
    std::list<std::shared_ptr<DNSRecord>> anlist, nslist, arlist;
    int qdcount = 0, ancount = 0, nscount = 0, arcount = 0;

    int success = append_question(qj->key, &qlist, &anlist, &packetSize,
            &qdcount, &ancount, is_private);
    done(qj);

    // now try to append more questions if we didn't already exceed the packet size.
    std::list<std::shared_ptr<MDNSQueryJob>> done_records;
    if (!is_private) { // only if we don't have a private query job
        for (auto job : jobs) {
            // take another query job from the list..
            if(!success) break;

            int _private_job = 0;
            std::string service_type = ODnsExtension::extract_stype(
                    job->key->name);

            // check whether this service is private, do not append it if it is
            if (hasPrivacy
                    && private_service_table->find(service_type)
                            != private_service_table->end()) {
                std::shared_ptr<ODnsExtension::PrivateMDNSService> psrv =
                        (*private_service_table)[service_type];
                _private_job = psrv->is_private;
                // reschedule
                timeEventSet->updateTimeEvent(job->e,
                        simTime() + STR_SIMTIME("20ms"));
            }

            if (!_private_job) {
                success = append_question(job->key, &qlist, &anlist,
                        &packetSize, &qdcount, &ancount, 0);
            }
            if (!_private_job) {
                done_records.push_back(job);
            }
        }

        for(auto job : done_records) done(job);
    }

    if (preparePacketAndSend(qlist, anlist, nslist, arlist, qdcount, ancount,
            nscount, arcount, packetSize, !success, is_private)) {
        // success, delegate?
    } else {
        // some error message?
    }

}

int MDNSQueryScheduler::preparePacketAndSend(
        std::list<std::shared_ptr<DNSQuestion>> qlist,
        std::list<std::shared_ptr<DNSRecord>> anlist,
        std::list<std::shared_ptr<DNSRecord>> nslist,
        std::list<std::shared_ptr<DNSRecord>> arlist, int qdcount, int ancount,
        int nscount, int arcount, int packetSize, int TC, int is_private) {

    std::string msgname;
    if (!is_private)
        msgname = "MDNS_query#";
    else
        msgname = "PRIVATE_query#";

    msgname += std::to_string(id_count);

    DNSPacket* p = ODnsExtension::createNQuery(msgname, qdcount, ancount,
            nscount, arcount, id_count++, 0);

    int i = 0;
    // append questions
    for (auto it : qlist) {
        ODnsExtension::appendQuestion(p, it, i);
        i++;
    }

    // append answers if available
    if (ancount > 0) {
        i = 0;
        for (auto it : anlist) {
            ODnsExtension::appendAnswer(p, it, i);
            i++;
        }
    }

    // append auth if available
    if (nscount > 0) {
        i = 0;
        for (auto it : nslist) {
            ODnsExtension::appendAuthority(p, it, i);
            i++;
        }
    }

    // append add if available
    if (arcount > 0) {
        i = 0;
        for (auto it : arlist) {
            ODnsExtension::appendAdditional(p, it, i);
            i++;
        }
    }

    std::unordered_map<std::string, int> signalPars;
    signalPars["signal_type"] = 1;

    // packet fully initialized, send it via multicast
    p->setByteLength(ODnsExtension::estimateDnsPacketSize(p));
    p->addPar("prettyContent");
    p->par("prettyContent") = ODnsExtension::dnsPacketToString(p).c_str();
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
        std::string service_type = ODnsExtension::extract_stype(
                p->getQuestions(0).qname);
        std::shared_ptr<ODnsExtension::PrivateMDNSService> psrv =
                (*private_service_table)[service_type];
        // go through the offered_to list
        p->addPar("private");
        p->par("private") = true;
        signalPars["privacy"] = 1;
        signalReceiver->receiveSignal(signalPars, p);

        for (auto it : psrv->offered_to) {
            std::string key = it;
            std::shared_ptr<ODnsExtension::FriendData> fdata =
                    (*friend_data_table)[key];
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

int MDNSQueryScheduler::append_question(std::shared_ptr<MDNSKey> key,
        std::list<std::shared_ptr<DNSQuestion>>* qlist,
        std::list<std::shared_ptr<DNSRecord>>* anlist, int *packetSize,
        int* qdcount, int* ancount, int is_private) {
    std::list<std::shared_ptr<DNSRecord>> knownAnswers; // append known answers from the cache in here

    std::shared_ptr<ODnsExtension::DNSQuestion> q;
    q = createQuestionFromKey(key);

    int qsize = sizeof(key->name) + 4; // name length + 4 bytes for type and class

    if (*packetSize + qsize > MAX_MDNS_PACKET_SIZE) {
        return 0;
    }

    *packetSize += qsize;

    (*qdcount)++; // this throws a warning, but we actually want to increase the referenced value ..
    (*qlist).push_back(q);

    // append known answers for this query
    if (!is_private) { // do not append KA if the query job is private
        knownAnswers = append_cache_entries(key, knownAnswers);

        // try to append known answers, as long as max size is not exceeded
        for (auto it = knownAnswers.begin(); it != knownAnswers.end(); ++it) {
            std::shared_ptr<DNSRecord> record = *it;

            // calculate size
            int size = 10 + sizeof(record->rname) + record->rdlength;

            if (*packetSize + size > MAX_MDNS_PACKET_SIZE) {
                return 0;
            }

            *packetSize += size;

            // append record to answer list
            (*ancount)++;
            (*anlist).push_back(record);
        }
    }
    // all answers were appended, return success
    return 1;
}

std::list<std::shared_ptr<DNSRecord>> MDNSQueryScheduler::append_cache_entries(
        std::shared_ptr<MDNSKey> key,
        std::list<std::shared_ptr<DNSRecord>> list) {
    std::string hash = key->name + std::string(":")
            + std::string(getTypeStringForValue(key->type)) + std::string(":")
            + std::string(getClassStringForValue(key->_class));
    std::list<std::shared_ptr<DNSRecord>> from_cache = cache->get_from_cache(
            hash);
    std::shared_ptr<DNSRecord> record;

    for (auto it = from_cache.begin(); it != from_cache.end(); ++it) {
        record = *it;

        // try to append known answer if halfTTL not outlived..
        if (cache->halfTTL(record)) {
            // everything is fine, we can append the answer..
            // FIXME: create a copy of the record, this way it is
            // too unsafe.
            list.push_back(record);
        }
    }

    return list;

}

std::shared_ptr<ODnsExtension::MDNSQueryJob> MDNSQueryScheduler::find_job(
        std::shared_ptr<ODnsExtension::MDNSKey> key) {
    std::shared_ptr<ODnsExtension::MDNSQueryJob> qj;

    for (auto it = jobs.begin(); it != jobs.end(); ++it) {
        qj = *it;
        if (!ODnsExtension::compareMDNSKey(key, qj->key)) {
            return qj;
        }
    }

    return NULL;

}

std::shared_ptr<ODnsExtension::MDNSQueryJob> MDNSQueryScheduler::find_history(
        std::shared_ptr<ODnsExtension::MDNSKey> key) {
    std::shared_ptr<ODnsExtension::MDNSQueryJob> qj;

    for (auto it = history.begin(); it != history.end(); ++it) {
        qj = *it;
        if (!ODnsExtension::compareMDNSKey(key, qj->key)) {
            return qj;
        }
    }

    return NULL;
}

void MDNSQueryScheduler::post(std::shared_ptr<ODnsExtension::MDNSKey> key,
        int immediately) {
    std::shared_ptr<MDNSQueryJob> qj;
    simtime_t tv;

    if ((qj = find_history(key)))
        return;

    if (!immediately) {
        int defer = intrand(100) + 20;
        // create simtime value from random deferral value
        std::string stime = std::to_string(defer) + std::string("ms");
        tv = simTime() + STR_SIMTIME(stime.c_str());

    } else {
        tv = simTime();
    }

    // update time if this question is a duplicate
    if ((qj = find_job(key))) {
        if (tv < qj->delivery) {
            qj->delivery = tv;
            timeEventSet->updateTimeEvent(qj->e, tv);
        }
    } else {
        // create new job..
        qj = new_job(key);
        qj->delivery = tv;

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(qj);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSQueryScheduler::elapseCallback);

        qj->e = e;
        timeEventSet->addTimeEvent(e);

    }

    std::shared_ptr<SimTime> tv_ptr(new SimTime(tv));

    callback(tv_ptr, resolver);

}

void MDNSQueryScheduler::done(std::shared_ptr<ODnsExtension::MDNSQueryJob> qj) {
    qj->done = 1;

    auto it = std::find(jobs.begin(), jobs.end(), qj);
    if (it != jobs.end()) {
        jobs.erase(it);
    }
    if (std::find(history.begin(), history.end(), qj) == history.end())
        return;

    history.push_back(qj);

    simtime_t now = simTime();
    qj->delivery = now;

    // update the time event

    // add random deferral value between 20 and 120
    int defer = intrand(100) + 20;
    // create simtime value from random deferral value
    std::string stime = std::to_string(defer) + std::string("ms");
    simtime_t tv = STR_SIMTIME(stime.c_str());

    timeEventSet->updateTimeEvent(qj->e, now + tv);
}

void MDNSQueryScheduler::check_dup(
        std::shared_ptr<ODnsExtension::MDNSKey> key) {
    std::shared_ptr<MDNSQueryJob> qj;

    if ((qj = find_job(key))) {
        // found a matching upcoming job, we don't need
        // to perform it anymore, since another node
        // queried for it.

        done(qj);
        return;
    }

    // add random deferral value between 20 and 120
    int defer = intrand(100) + 20;
    // create simtime value from random deferral value
    std::string stime = std::to_string(defer) + std::string("ms");
    simtime_t tv = simTime() + STR_SIMTIME(stime.c_str());

    if ((qj = find_history(key))) {
        // just update the time for the existing job
        qj->delivery = tv;
        timeEventSet->updateTimeEvent(qj->e, tv);
    }

}

std::shared_ptr<ODnsExtension::MDNSQueryJob> MDNSQueryScheduler::new_job(
        std::shared_ptr<ODnsExtension::MDNSKey> key) {
    std::shared_ptr<MDNSQueryJob> qj(new MDNSQueryJob());
    qj->id = id_count++;
    qj->key = std::shared_ptr < MDNSKey > (new MDNSKey());
    qj->key->name = key->name;
    qj->key->type = key->type;
    qj->key->_class = key->_class;

    qj->done = 0;

    jobs.push_back(qj);

    return qj;
}

void MDNSQueryScheduler::remove_job(
        std::shared_ptr<ODnsExtension::MDNSQueryJob> qj) {
    timeEventSet->removeTimeEvent(qj->e);

    if (find_job(qj->key)) {
        auto it = std::find(jobs.begin(), jobs.end(), qj);
        if (it != jobs.end()) {
            jobs.erase(it);
        }

        return;
    } else if (find_history(qj->key)) {
        auto it = std::find(history.begin(), history.end(), qj);
        if (it != history.end()) {
            history.erase(it);
        }

        return;
    }

    // no ref found? i.e. just delete ...
    qj.reset();
}

} /* namespace ODnsExtension */
