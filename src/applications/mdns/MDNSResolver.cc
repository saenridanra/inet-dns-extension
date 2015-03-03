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

#include "MDNSResolver.h"

Define_Module(MDNSResolver);

MDNSResolver::MDNSResolver() {
}

MDNSResolver::~MDNSResolver() {
    // delete objects used in here..
    g_free(hostname);
    delete timeEventSet;
    delete probeScheduler;
    delete queryScheduler;
    delete responseScheduler;
}

void MDNSResolver::initialize(int stage) {
    if (stage == 0) {
        outSock.setOutputGate(gate("mdnsOut"));
        outSock.bind(MDNS_PORT);
        outSock.setTimeToLive(15);

    } else if (stage == 3) {
        timeEventSet = new ODnsExtension::TimeEventSet();
        selfMessage = new cMessage("timer");
        selfMessage->setKind(MDNS_KIND_TIMER);

        outSock.joinLocalMulticastGroups();

        last_schedule = simTime() + elapseTime;
        scheduleAt(last_schedule, selfMessage);

        cache = new ODnsExtension::DNSTTLCache();

        probeScheduler = new ODnsExtension::MDNSProbeScheduler(timeEventSet,
                &outSock, this);
        probeScheduler->setCache(cache);
        probeScheduler->setCallback(MDNSResolver::callback);
        queryScheduler = new ODnsExtension::MDNSQueryScheduler(timeEventSet,
                &outSock, this);
        queryScheduler->setCache(cache);
        queryScheduler->setCallback(MDNSResolver::callback);
        responseScheduler = new ODnsExtension::MDNSResponseScheduler(
                timeEventSet, &outSock, this);
        responseScheduler->setCache(cache);
        responseScheduler->setCallback(MDNSResolver::callback);

        hostname = g_strdup(par("hostname").stringValue());
        hostaddress = IPvXAddressResolver().addressOf(this->getParentModule());

        services = NULL;
        initializeServices();

        announcer = new ODnsExtension::MDNSAnnouncer(probeScheduler,
                responseScheduler, timeEventSet, services, hostname,
                &hostaddress);

        announcer->initialize();
    }
}

void MDNSResolver::handleMessage(cMessage *msg) {
    if (msg->isSelfMessage()) {
        if (msg->getKind() == MDNS_KIND_TIMER) {
            elapsedTimeCheck();
            return;
        }
    } else {
        // check which kind it is
        if (msg->getKind() == MDNS_KIND_INTERNAL_QUERY) {
            // this is a message from a module utilizing the mdns resolver
            // and wanting to perform a query..
            delete msg;
            return;
        } else if (msg->getKind() == MDNS_KIND_INTERNAL_PUBLISH) {
            // a higher layer application wants to publish a service
            delete msg;
            return;
        } else if (msg->getKind() == MDNS_KIND_INTERNAL_REVOKE) {
            // a higher layer application wants to revoke a service offered
            delete msg;
            return;
        } else if (msg->getKind() == UDP_I_DATA) {
            DNSPacket* p = check_and_cast<DNSPacket*>(msg);
            UDPDataIndication *ctrl = check_and_cast<UDPDataIndication *>(
                    p->getControlInfo());
            IPvXAddress srcAddress = ctrl->getSrcAddr();

            if (srcAddress.get4() != hostaddress.get4()) {
                if (ODnsExtension::isQuery(p)) {
                    handleQuery(p);
                } else if (ODnsExtension::isResponse(p)) {
                    handleResponse(p);
                }
            }

            delete msg;
            return;
        }
    }
}

void MDNSResolver::elapsedTimeCheck() {

    // perform a cache cleanup, every entry that has passed
    // it's TTL was not successfully updated
    cache->cleanup();

    // check if we have an event coming up now, i.e. check if we can get
    // an event from the timeEventSet
    ODnsExtension::TimeEvent* event;
    if ((event = timeEventSet->getTimeEventIfDue())) {
        // perform the timeEvent..
        event->performCallback(); // the rest is handled in the callback
    }

    event = timeEventSet->getTopElement();

    // first, schedule new elapseTimeCheck

    if (event) {
        scheduleAt(event->getExpiry(), selfMessage);
        last_schedule = event->getExpiry();
    }

}

void MDNSResolver::callback(void* data, void* thispointer) {
    MDNSResolver * self = static_cast<MDNSResolver*>(thispointer);
    self->scheduleSelfMessage(*(simtime_t*) data);
}

void MDNSResolver::scheduleSelfMessage(simtime_t tv) {
    if (tv < last_schedule) {
        cancelEvent(selfMessage);
        scheduleAt(tv, selfMessage);
    }
}

void MDNSResolver::handleQuery(DNSPacket* p) {
    // go through the ns section of the query
    GList* record_list = NULL;

    // go through the question section, find out which answers to respond with
    for (int i = 0; i < p->getQdcount(); i++) {
        ODnsExtension::DNSQuestion question = p->getQuestions(i);
        ODnsExtension::MDNSKey* key = ODnsExtension::mdns_key_new(
                question.qname, question.qtype, question.qclass);
        // allow suppression if there are no answers for this query
        // and the tc flag is not set
        if (p->getAncount() == 0 && !DNS_HEADER_TC(p->getOptions()))
            queryScheduler->check_dup(key);

        // prepare matching responses
        GList* announced_records = announcer->get_announced_services();

        while (announced_records) {
            // check if the record matches the key, if so append it to the answer list
            DNSRecord* r = (DNSRecord*) announced_records->data;
            ODnsExtension::MDNSKey* record_key = ODnsExtension::mdns_key_new(
                    r->rname, r->rtype, r->rclass);

            // ANY Question
            if (key->type == DNS_TYPE_VALUE_ANY) {
                // only compare name and class
                if (ODnsExtension::compareMDNSKeyANY(key, record_key)) {
                    record_list = g_list_append(record_list, r);
                }
            } // Normal Question
            else {
                if (ODnsExtension::compareMDNSKey(key, record_key)) {
                    record_list = g_list_append(record_list, r);
                }
            }

            // If the question did non include ANY or CNAME, we did not check for CNAMEs just yet
            if (key->type != DNS_TYPE_VALUE_CNAME
                    && key->type != DNS_TYPE_VALUE_ANY) {
                ODnsExtension::MDNSKey* cname_key = ODnsExtension::mdns_key_new(
                        question.qname, DNS_TYPE_VALUE_CNAME, question.qclass);
                if (ODnsExtension::compareMDNSKey(cname_key, record_key)) {
                    record_list = g_list_append(record_list, r);
                }

                // free the cname key
                ODnsExtension::mdns_key_free(cname_key);
            }

            ODnsExtension::mdns_key_free(record_key);
            announced_records = g_list_next(announced_records);
        }

        // free the question key
        ODnsExtension::mdns_key_free(key);
    }

    // go through the answer section and perform KAS
    IPvXAddress* querier = &(check_and_cast<UDPDataIndication *>(
            p->getControlInfo()))->getSrcAddr();
    for (int i = 0; i < p->getAncount(); i++) {
        DNSRecord* answer = &p->getAnswers(i);
        responseScheduler->suppress(answer, 0, querier, 0);
        // remove records that we may have appended to the list
        // since the records pointers are different we have to go through the list ..
        GList* next = g_list_first(record_list);
        while (next) {
            DNSRecord* in_record = (DNSRecord*) next->data;
            next = g_list_next(next);
            if (!g_strcmp0(answer->rname, in_record->rname)
                    && !g_strcmp0(answer->rdata, in_record->rdata)
                    && answer->rtype == in_record->rtype
                    && answer->rclass == in_record->rclass) {
                // remove the record from the list ..
                record_list = g_list_remove(record_list, in_record);
            }
        }
    }

    // now check probes and check whether they collide
    for (int i = 0; i < p->getNscount(); i++) {
        DNSRecord* ns_record = (DNSRecord*) &p->getAuthorities(i);
        announcer->check_conflict(ns_record); // check whether we have a problem
    }

    // we're finished, now let's post the responses
    GList* next = g_list_first(record_list);
    while (next) {
        responseScheduler->post((DNSRecord*) next->data, 0, querier,
                p->getNscount() > 0);
        next = g_list_next(record_list);
    }
}

void MDNSResolver::handleResponse(DNSPacket* p) {
    // go through the answer list of the packet
    std::string bubble_popup = "";
    for (int i = 0; i < p->getAncount(); i++) {
        // check if the record conflicts, if not put it into the cache
        DNSRecord* r = &p->getAnswers(i);
        if (r->rtype != DNS_TYPE_VALUE_ANY) {
            if (!announcer->check_conflict(r)) {
                // put the record into the cache
                bubble_popup.append("New cache entry:\n");
                bubble_popup.append(r->rname);
                bubble_popup.append(":");
                bubble_popup.append(ODnsExtension::getTypeStringForValue(r->rtype));
                bubble_popup.append(":");
                bubble_popup.append(ODnsExtension::getClassStringForValue(r->rclass));
                bubble_popup.append("\nData: ");
                bubble_popup.append(r->rdata);
                bubble_popup.append("\n---------\n");

                cache->put_into_cache(ODnsExtension::copyDnsRecord(r));
                responseScheduler->check_dup(r, 0);
            }
        }
    }

    if(bubble_popup != ""){
        EV << bubble_popup.c_str();
        this->getParentModule()->bubble(bubble_popup.c_str());
    }
}

void MDNSResolver::initializeServices() {
    const char* service_files = par("service_files").stringValue();
    // go through all files and initialize them as MDNS services
    cStringTokenizer tokenizer(service_files);
    const char *token;

    while (tokenizer.hasMoreTokens()) {
        // initialize service file
        token = tokenizer.nextToken();
        initializeServiceFile(token);
    }
}

void MDNSResolver::initializeServiceFile(const char* file) {
    std::string line;
    std::fstream service_file(file, std::ios::in);
    int error = 0;

    ODnsExtension::MDNSService* service = (ODnsExtension::MDNSService*) malloc(
            sizeof(*service));
    service->txtrecords = NULL;

    while (getline(service_file, line, '\n')) {

        if (line.empty() || line[0] == ';') {

            continue;
        }

        // use a tokenizer to interpret the line
        std::vector<std::string> tokens =
                cStringTokenizer(line.c_str(), "=").asVector();

        if (tokens.size() != 2) {
            continue; // we have exactly two tokens vor our key value pairs
        }

        if (tokens[0] == "service_type") {
            service->service_type = g_strdup(tokens[1].c_str());
        } else if (tokens[0] == "instance_name") {
            service->name = g_strdup(tokens[1].c_str());
        } else if (tokens[0] == "txt_record") {
            service->txtrecords = g_list_append(service->txtrecords,
                    g_strdup(tokens[1].c_str()));
        } else if (tokens[0] == "port") {
            char* tail;
            service->port = strtol(tokens[1].c_str(), &tail, 10);
        } else {
            error = 1;
            cRuntimeError("Malformed service file %s", file);
        }

    }

    if (!error) {
        services = g_list_append(services, service);
    }

}
