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
#include <MDNSAnnouncer.h>

namespace ODnsExtension {

void MDNSAnnouncer::initialize() {
    // add host probes, i.e. hostname.local A, AAAA record
    if (s == AnnouncerState::START || s == AnnouncerState::RESTART) {
        probing = NULL;
        auth_cache = new ODnsExtension::DNSTTLCache();

        DNSRecord* a_record = (DNSRecord*) malloc(sizeof(*a_record));
        DNSRecord* a_ptr_record = (DNSRecord*) malloc(sizeof(*a_ptr_record));

        // populate records
        target = g_strdup_printf("%s.local", hostname);
        a_record->rname = g_strdup(target);
        a_record->rtype = DNS_TYPE_VALUE_A;
        a_record->rclass = DNS_CLASS_IN;
        a_record->rdata = g_strdup(hostaddress->get4().str().c_str()); // actual host address
        a_record->rdlength = strlen(hostaddress->get4().str().c_str());
        a_record->ttl = MDNS_HOST_TTL;

        // generate inverse records as well
        a_ptr_record->rname = g_strdup_printf("%s.in-addr.arpa.",
                hostaddress->get4().str().c_str());
        a_ptr_record->rtype = DNS_TYPE_VALUE_PTR;
        a_ptr_record->rclass = DNS_CLASS_IN;
        a_ptr_record->rdata = g_strdup(target);
        a_ptr_record->rdlength = sizeof(target) - 1;
        a_ptr_record->ttl = MDNS_HOST_TTL;

        // now add records to the list, create a time out, that is soon scheduled

        Probe* a = (Probe*) malloc(sizeof(*a));
        Probe* a_ptr = (Probe*) malloc(sizeof(*a_ptr));

        a->n_iter = 0;
        a->collision_count = 1;
        a->r = a_record;
        a->s = ProbeState::STARTING;
        a->probe_id = (uint32_t*) malloc(sizeof(a->probe_id));
        *a->probe_id = id_internal++;

        a_ptr->n_iter = 0;
        a_ptr->collision_count = 1;
        a_ptr->r = a_ptr_record;
        a_ptr->s = ProbeState::STARTING;
        a_ptr->probe_id = (uint32_t*) malloc(sizeof(a_ptr->probe_id));
        *a_ptr->probe_id = id_internal++;

        probing = g_list_append(probing, a);
        probing = g_list_append(probing, a_ptr);

        simtime_t tv = simTime() + STR_SIMTIME("20ms");

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(a);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSAnnouncer::elapseCallback);
        timeEventSet->addTimeEvent(e);
        a->e = e;

        e = new ODnsExtension::TimeEvent(this);
        e->setData(a_ptr);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSAnnouncer::elapseCallback);
        timeEventSet->addTimeEvent(e);
        a_ptr->e = e;

        if (hostaddress->isIPv6()) {
            // do the same as above just with  AAAA record
            DNSRecord* aaaa_record = (DNSRecord*) malloc(sizeof(*aaaa_record));
            DNSRecord* aaaa_ptr_record = (DNSRecord*) malloc(
                    sizeof(*aaaa_ptr_record));
            aaaa_record->rname = g_strdup(target);
            aaaa_record->rtype = DNS_TYPE_VALUE_AAAA;
            aaaa_record->rclass = DNS_CLASS_IN;
            aaaa_record->rdata = g_strdup(hostaddress->get6().str().c_str()); // actual host address
            aaaa_record->rdlength = strlen(hostaddress->get6().str().c_str());
            aaaa_record->ttl = MDNS_HOST_TTL;

            aaaa_ptr_record->rname = g_strdup_printf("%s.ip6.arpa.",
                    hostaddress->get6().str().c_str());
            aaaa_ptr_record->rtype = DNS_TYPE_VALUE_PTR;
            aaaa_ptr_record->rclass = DNS_CLASS_IN;
            aaaa_ptr_record->rdata = g_strdup(target);
            aaaa_ptr_record->rdlength = sizeof(target) - 1;
            aaaa_ptr_record->ttl = MDNS_HOST_TTL;

            Probe* aaaa = (Probe*) malloc(sizeof(*aaaa));
            Probe* aaaa_ptr = (Probe*) malloc(sizeof(*aaaa_ptr));

            aaaa->n_iter = 0;
            aaaa->collision_count = 1;
            aaaa->r = aaaa_record;
            aaaa->s = ProbeState::STARTING;
            aaaa->probe_id = (uint32_t*) malloc(sizeof(aaaa->probe_id));
            *aaaa->probe_id = id_internal++;
            aaaa_ptr->n_iter = 0;
            aaaa_ptr->collision_count = 1;
            aaaa_ptr->r = aaaa_record;
            aaaa_ptr->s = ProbeState::STARTING;
            aaaa_ptr->probe_id = (uint32_t*) malloc(sizeof(aaaa_ptr->probe_id));
            *aaaa_ptr->probe_id = id_internal++;

            probing = g_list_append(probing, aaaa);
            probing = g_list_append(probing, aaaa_ptr);

            e = new ODnsExtension::TimeEvent(this);
            e->setData(aaaa);
            e->setExpiry(tv);
            e->setLastRun(0);
            e->setCallback(ODnsExtension::MDNSAnnouncer::elapseCallback);
            timeEventSet->addTimeEvent(e);
            aaaa->e = e;

            e = new ODnsExtension::TimeEvent(this);
            e->setData(aaaa_ptr);
            e->setExpiry(tv);
            e->setLastRun(0);
            e->setCallback(ODnsExtension::MDNSAnnouncer::elapseCallback);
            timeEventSet->addTimeEvent(e);
            aaaa_ptr->e = e;
        }

    } else if (s == AnnouncerState::PROBE) {
        // add service probes
        GList* next = g_list_first(to_announce);

        // add entries to the starting list and create a timeout event, so the callback is performed..
        while (next) {
            MDNSService* s = (MDNSService*) next->data;
            add_service(s);
            next = g_list_next(next);
        }
    }
}

void MDNSAnnouncer::restart() {

}

void MDNSAnnouncer::add_service(MDNSService* service) {
    // Create an SRV record for the service
    DNSRecord* service_record = (DNSRecord*) malloc(sizeof(*service_record));
    char* label = g_strdup_printf("%s.%s", service->name,
            service->service_type);

    service_record->rname = g_strdup(label);
    service_record->rtype = DNS_TYPE_VALUE_SRV;
    service_record->rclass = DNS_CLASS_IN;
    service_record->rdata = g_strdup(target);
    service_record->rdlength = strlen(target);
    service_record->ttl = 60 * 75;

    Probe* p = (Probe*) malloc(sizeof(*p));
    p->n_iter = 0;
    p->collision_count = 1;
    p->r = service_record;
    p->s = ProbeState::STARTING;
    p->probe_id = (uint32_t*) malloc(sizeof(p->probe_id));
    *p->probe_id = id_internal++;
    p->ref_service = service;

    probing = g_list_append(probing, p);

    simtime_t tv = simTime() + STR_SIMTIME("20ms");

    ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
    e->setData(p);
    e->setExpiry(tv);
    e->setLastRun(0);
    e->setCallback(ODnsExtension::MDNSAnnouncer::elapseCallback);
    p->e = e;
    timeEventSet->addTimeEvent(e);

    // go through all txt records
    if (service->txtrecords) {
        GList* next = g_list_first(service->txtrecords);
        while (next) {
            DNSRecord* txtrecord = (DNSRecord*) malloc(sizeof(*txtrecord));
            txtrecord->rname = g_strdup(label);
            txtrecord->rtype = DNS_TYPE_VALUE_TXT;
            txtrecord->rclass = DNS_CLASS_IN;
            txtrecord->rdata = g_strdup((char*) next->data);
            txtrecord->rdlength = sizeof(next->data) - 1;
            txtrecord->ttl = MDNS_SERVICE_TTL;

            p = (Probe*) malloc(sizeof(*p));
            p->n_iter = 0;
            p->collision_count = 1;
            p->r = txtrecord;
            p->s = ProbeState::STARTING;
            p->probe_id = (uint32_t*) malloc(sizeof(p->probe_id));
            *p->probe_id = id_internal++;
            p->ref_service = service;

            e = new ODnsExtension::TimeEvent(this);
            e->setData(p);
            e->setExpiry(tv);
            e->setLastRun(0);
            e->setCallback(ODnsExtension::MDNSAnnouncer::elapseCallback);
            timeEventSet->addTimeEvent(e);

            p->e = e;

            next = g_list_next(next);
        }
    } else {
        // add an empty txt record..
        DNSRecord* txtrecord = (DNSRecord*) malloc(sizeof(*txtrecord));
        char* txt = g_strdup("");
        txtrecord->rname = g_strdup(label);
        txtrecord->rtype = DNS_TYPE_VALUE_TXT;
        txtrecord->rclass = DNS_CLASS_IN;
        txtrecord->rdata = txt;
        txtrecord->rdlength = 0;
        txtrecord->ttl = MDNS_SERVICE_TTL;

        p = (Probe*) malloc(sizeof(*p));
        p->n_iter = 0;
        p->collision_count = 1;
        p->r = txtrecord;
        p->s = ProbeState::STARTING;
        p->probe_id = (uint32_t*) malloc(sizeof(p->probe_id));
        *p->probe_id = id_internal++;

        e = new ODnsExtension::TimeEvent(this);
        e->setData(p);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSAnnouncer::elapseCallback);
        timeEventSet->addTimeEvent(e);

        p->e = e;
    }

    g_free(label);
}

GList* MDNSAnnouncer::get_announced_services() {
    GHashTableIter iterator;
    gpointer key, value;
    GList* announced_records = NULL;

    g_hash_table_iter_init(&iterator, probe_to_cache);
    while (g_hash_table_iter_next(&iterator, &key, &value)) {
        // use the hash in &value to get the record and append it to the list
        GList* from_cache = auth_cache->get_from_cache((char*) value);
        // append the list to our list
        announced_records = g_list_concat(announced_records, from_cache);
    }

    return announced_records;
}

int MDNSAnnouncer::check_conflict(DNSRecord* r) {
    // check if probe list is non-empty

    GList* next = g_list_first(probing);
    int conflict = 0;

    while (next) {
        Probe* p = (Probe*) next->data;

        if (!g_strcmp0(p->r->rname, r->rname)
                && !g_strcmp0(p->r->rdata, r->rdata) && p->r->rtype == r->rtype
                && p->r->rclass == r->rclass) {
            conflict = 1;
            break; // the other host announces the exact same record, we're finished here
        } else if (!g_strcmp0(p->r->rname, r->rname)
                && g_strcmp0(p->r->rdata, r->rdata) && p->r->rtype == r->rtype
                && p->r->rclass == r->rclass && p->s == ProbeState::PROBING) {
            // we have a conflict, remove the probe, and try with another label
            // since there may be more probes matching this label, we withdraw all of them
            withdraw(p);
            conflict = 1;
        } else {
            // we're already announcing the probe, it belongs to us
            break;
        }

        next = g_list_next(next);
    }

    return conflict;
}

void MDNSAnnouncer::withdraw(Probe* p) {
    // by withdrawing, the label is changed and the probing number reset
    p->n_iter = 0;
    char* label_new = g_strdup_printf("%s-%d.%s", p->ref_service->name,
            ++p->collision_count, p->ref_service->service_type);
    g_free(p->r->rname);
    // use the new label..
    p->s = ProbeState::PROBING;
    p->r->rname = label_new;
}

void MDNSAnnouncer::goodbye(Probe* p, int send_goodbye, int remove) {
    if (send_goodbye) {
        if (p->s == ProbeState::ANNOUNCING) {
            DNSRecord* goodbye_record = ODnsExtension::copyDnsRecord(p->r);
            goodbye_record->ttl = 0;
            response_scheduler->post(goodbye_record, 0, NULL, 0);
        }
    }

    if (remove) {
        // delete the probe and related time events
        timeEventSet->removeTimeEvent(p->e);
        // deallocate memory
        freeDnsRecord(p->r);
        delete p->e;
        free(p->probe_id);
        g_free(p->ref_service->name);
        g_free(p->ref_service->service_type);
        GList* txtrecords = p->ref_service->txtrecords;
        while (txtrecords) {
            free(txtrecords->data);
            txtrecords = g_list_next(txtrecords);
        }
        free(p);
    }
}

void MDNSAnnouncer::elapse(ODnsExtension::TimeEvent* e, void* data) {
    Probe* p = (Probe*) data;
    simtime_t tv;
    // no probe has been sent out so far..
    if (p->s == ProbeState::STARTING) {
        // do the first probe
        p->n_iter++;
        probe_scheduler->post(p->r, 0);
        p->s = ProbeState::PROBING;

        // 250msec delay
        tv = simTime() + STR_SIMTIME("250ms");
        timeEventSet->updateTimeEvent(p->e, tv);

    } else if (p->s == ProbeState::PROBING) {
        if (p->n_iter > 2) {
            // we're finished probing, start announcing
            // send first response for probe
            p->n_iter = 1;
            p->s = ProbeState::ANNOUNCING;
            response_scheduler->post(p->r, 1, NULL, 0);

            // add 2^(p->n_iter - 1) * 1s delay
            tv = simTime()
                    + ((int) pow(2, (p->n_iter - 1)) * STR_SIMTIME("1s"));
            timeEventSet->updateTimeEvent(p->e, tv);
        } else {
            // still need to send out some probes
            p->n_iter++;
            probe_scheduler->post(p->r, 0);
            // 250msec delay
            tv = simTime() + STR_SIMTIME("250ms");
            timeEventSet->updateTimeEvent(p->e, tv);
        }
    } else if (p->s == ProbeState::ANNOUNCING) {
        if (p->n_iter > 3) {
            p->s = ProbeState::ANNOUNCED;
            p->n_iter = 0;
            // add record to cache..

            auth_cache->put_into_cache(p->r); // using the cache, we know when the record is up for eviction
            char* hash = g_strdup_printf("%s%s%s", p->r->rname,
                    getTypeStringForValue(p->r->rtype),
                    getClassStringForValue(p->r->rclass));
            g_hash_table_insert(probe_to_cache, p->probe_id, hash);

            if (s == AnnouncerState::START || s == AnnouncerState::RESTART) {
                s = AnnouncerState::PROBE;
                initialize();
            } else if (s == AnnouncerState::PROBE) {
                s = AnnouncerState::FINISHED;
            }
        } else {
            // still have to send out annoucements
            p->n_iter++;
            response_scheduler->post(p->r, 1, NULL, 0);

            // add 2^(p->n_iter - 1) * 1s delay
            tv = simTime()
                    + (((int) pow(2, (p->n_iter - 1)) * STR_SIMTIME("1s")));
            timeEventSet->updateTimeEvent(p->e, tv);
        }
    }
}

} /* namespace ODnsExtension */
