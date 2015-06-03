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

namespace INETDNS {

void MDNSAnnouncer::initialize()
{
    // add host probes, i.e. hostname.local A, AAAA record
    if (s == AnnouncerState::START || s == AnnouncerState::RESTART)
    {
        auth_cache = new INETDNS::DNSTTLCache();

        std::shared_ptr<DNSRecord> a_record(new DNSRecord());
        std::shared_ptr<DNSRecord> a_ptr_record(new DNSRecord());

        // populate records
        target = hostname + std::string(".local");
        a_record->rname = target;
        a_record->rtype = DNS_TYPE_VALUE_A;
        a_record->rclass = DNS_CLASS_IN;
        a_record->strdata = std::string(hostaddress->get4().str()); // actual host address
        a_record->rdlength = a_record->strdata.length();
        a_record->ttl = MDNS_HOST_TTL;

        // generate inverse records as well
        a_ptr_record->rname = hostaddress->get4().str() + std::string(".in-addr.arpa.");
        a_ptr_record->rtype = DNS_TYPE_VALUE_PTR;
        a_ptr_record->rclass = DNS_CLASS_IN;
        a_ptr_record->strdata = std::string(target);
        a_ptr_record->rdlength = a_ptr_record->strdata.length();
        a_ptr_record->ttl = MDNS_HOST_TTL;

#ifdef DEBUG_ENABLED
        std::cout << "Creating announcing records for " << hostname << ":" << hostaddress->get4().str() << ":"
                << std::endl;
#endif

        INETDNS::printDNSRecord(a_record);
        INETDNS::printDNSRecord(a_ptr_record);

        // now add records to the list, create a time out, that is soon scheduled
        std::shared_ptr<Probe> a(new Probe());
        std::shared_ptr<Probe> a_ptr(new Probe());

        a->r = a_record;
        a->probe_id = id_internal++;
        a_ptr->r = a_ptr_record;
        a_ptr->probe_id = id_internal++;

        probing.push_back(a);
        probing.push_back(a_ptr);

        simtime_t tv = simTime() + STR_SIMTIME("20ms");

        INETDNS::TimeEvent* e = new INETDNS::TimeEvent(this);
        e->setData(a);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(INETDNS::MDNSAnnouncer::elapseCallback);
        timeEventSet->addTimeEvent(e);
        a->e = e;

        e = new INETDNS::TimeEvent(this);
        e->setData(a_ptr);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(INETDNS::MDNSAnnouncer::elapseCallback);
        timeEventSet->addTimeEvent(e);
        a_ptr->e = e;

        if (hostaddress->isIPv6())
        {
            // do the same as above just with  AAAA record
            std::shared_ptr<DNSRecord> aaaa_record(new DNSRecord());
            std::shared_ptr<DNSRecord> aaaa_ptr_record(new DNSRecord());
            aaaa_record->rname = target;
            aaaa_record->rtype = DNS_TYPE_VALUE_AAAA;
            aaaa_record->rclass = DNS_CLASS_IN;
            aaaa_record->strdata = std::string(hostaddress->get6().str()); // actual host address
            aaaa_record->rdlength = aaaa_record->strdata.length();
            aaaa_record->ttl = MDNS_HOST_TTL;

            aaaa_ptr_record->rname = hostaddress->get6().str() + std::string(".ip6.arpa.");
            aaaa_ptr_record->rtype = DNS_TYPE_VALUE_PTR;
            aaaa_ptr_record->rclass = DNS_CLASS_IN;
            aaaa_ptr_record->strdata = std::string(target);
            aaaa_ptr_record->rdlength = target.length();
            aaaa_ptr_record->ttl = MDNS_HOST_TTL;

            std::shared_ptr<Probe> aaaa(new Probe());
            std::shared_ptr<Probe> aaaa_ptr(new Probe());

            aaaa->r = aaaa_record;
            aaaa->probe_id = id_internal++;
            aaaa_ptr->r = aaaa_record;
            aaaa_ptr->probe_id = id_internal++;
            probing.push_back(aaaa);
            probing.push_back(aaaa_ptr);

            e = new INETDNS::TimeEvent(this);
            e->setData(aaaa);
            e->setExpiry(tv);
            e->setLastRun(0);
            e->setCallback(INETDNS::MDNSAnnouncer::elapseCallback);
            timeEventSet->addTimeEvent(e);
            aaaa->e = e;

            e = new INETDNS::TimeEvent(this);
            e->setData(aaaa_ptr);
            e->setExpiry(tv);
            e->setLastRun(0);
            e->setCallback(INETDNS::MDNSAnnouncer::elapseCallback);
            timeEventSet->addTimeEvent(e);
            aaaa_ptr->e = e;
        }

    }
    else if (s == AnnouncerState::PROBE)
    {
        // add entries to the starting list and create a timeout event, so the callback is performed..
        for (auto it : to_announce)
            add_service(it);
    }
}

void MDNSAnnouncer::restart()
{

}

void MDNSAnnouncer::add_service(std::shared_ptr<MDNSService> service)
{
    // Create an SRV record for the service
    std::shared_ptr<DNSRecord> service_record(new DNSRecord());
    std::string label = service->name + std::string(".") + service->service_type;

    service_record->rname = label;
    service_record->rtype = DNS_TYPE_VALUE_SRV;
    service_record->rclass = DNS_CLASS_IN;
    service_record->ttl = 60 * 75;

    std::shared_ptr<SRVData> srv(new SRVData());
    srv->name = label;
    srv->target = target;
    srv->service = service->service_type;
    srv->port = service->port;
    srv->ttl = 60 * 75;
    srv->weight = 0;
    srv->priority = 0;
    srv->proto = "_tcp"; // for now just stub tcp in..

    service_record->rdata = srv;
    service_record->rdlength = 6 + label.length() + target.length() + service->service_type.length();

    std::shared_ptr<Probe> p(new Probe());
    p->r = service_record;
    p->probe_id = id_internal++;
    p->ref_service = service;

    probing.push_back(p);

    simtime_t tv = simTime() + STR_SIMTIME("20ms");

    INETDNS::TimeEvent* e = new INETDNS::TimeEvent(this);
    e->setData(p);
    e->setExpiry(tv);
    e->setLastRun(0);
    e->setCallback(INETDNS::MDNSAnnouncer::elapseCallback);
    p->e = e;
    timeEventSet->addTimeEvent(e);

    // go through all txt records
    if (service->txtrecords.size() > 0)
    {
        for (auto it : service->txtrecords)
        {
            std::shared_ptr<DNSRecord> txtrecord(new DNSRecord());
            txtrecord->rname = label;
            txtrecord->rtype = DNS_TYPE_VALUE_TXT;
            txtrecord->rclass = DNS_CLASS_IN;
            txtrecord->strdata = it;
            txtrecord->rdlength = it.length();
            txtrecord->ttl = MDNS_SERVICE_TTL;

            p = std::shared_ptr < Probe > (new Probe());
            p->r = txtrecord;
            p->probe_id = id_internal++;
            p->ref_service = service;

            e = new INETDNS::TimeEvent(this);
            e->setData(p);
            e->setExpiry(tv);
            e->setLastRun(0);
            e->setCallback(INETDNS::MDNSAnnouncer::elapseCallback);
            timeEventSet->addTimeEvent(e);

            p->e = e;
        }
    }
    else
    {
        // add an empty txt record..
        std::shared_ptr<DNSRecord> txtrecord(new DNSRecord());
        std::string txt = "";
        txtrecord->rname = label;
        txtrecord->rtype = DNS_TYPE_VALUE_TXT;
        txtrecord->rclass = DNS_CLASS_IN;
        txtrecord->strdata = txt;
        txtrecord->rdlength = 0;
        txtrecord->ttl = MDNS_SERVICE_TTL;

        p = std::shared_ptr < Probe > (new Probe());
        p->r = txtrecord;
        p->probe_id = id_internal++;

        e = new INETDNS::TimeEvent(this);
        e->setData(p);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(INETDNS::MDNSAnnouncer::elapseCallback);
        timeEventSet->addTimeEvent(e);

        p->e = e;
    }
}

std::list<std::shared_ptr<DNSRecord>> MDNSAnnouncer::get_announced_services()
{
    std::list<std::shared_ptr<DNSRecord>> announced_records;

    for (auto kv : probe_to_cache)
    {
        // use the hash in &value to get the record and append it to the list
        std::list<std::shared_ptr<DNSRecord>> from_cache = auth_cache->get_from_cache(kv.second);
        // append the list to our list
        announced_records.insert(announced_records.end(), from_cache.begin(), from_cache.end());
    }

    return announced_records;
}

int MDNSAnnouncer::check_conflict(std::shared_ptr<DNSRecord> r)
{
    // check if probe list is non-empty
    int conflict = 0;

    for (auto p : probing)
    {
        if (INETDNS::recordDataEqual(r, p->r))
        {
            conflict = 1;
            break; // the other host announces the exact same record, we're finished here
        }
        else if (INETDNS::recordEqualNoData(r, p->r) && p->s == ProbeState::PROBING)
        {
            // we have a conflict, remove the probe, and try with another label
            // since there may be more probes matching this label, we withdraw all of them
            if ((r->rtype == DNS_TYPE_VALUE_SRV && p->r->rdata != r->rdata) || (p->r->strdata != r->strdata))
            {
                withdraw(p);
                conflict = 1;
            }
        }
        else
        {
            // we're already announcing the probe, it belongs to us
            break;
        }
    }

    return conflict;
}

void MDNSAnnouncer::withdraw(std::shared_ptr<Probe> p)
{
    // by withdrawing, the label is changed and the probing number reset
    p->n_iter = 0;
    std::string label_new = "";

    if (p->ref_service)
    {
        label_new = p->ref_service->name + std::string("-") + std::to_string(++p->collision_count) + std::string(".")
                + p->ref_service->service_type;
    }

    // use the new label..
    p->s = ProbeState::PROBING;
    p->r->rname = label_new;
}

void MDNSAnnouncer::goodbye(std::shared_ptr<Probe> p, int send_goodbye, int remove)
{
    if (send_goodbye)
    {
        if (p->s == ProbeState::ANNOUNCING)
        {
            std::shared_ptr<DNSRecord> goodbye_record = INETDNS::copyDnsRecord(p->r);
            goodbye_record->ttl = 0;
            response_scheduler->post(goodbye_record, 0, NULL, 0);
        }
    }

    if (remove)
    {
        // delete the probe and related time events
        timeEventSet->removeTimeEvent(p->e);
        freeDnsRecord(p->r);
        delete p->e;
        p.reset();
    }
}

void MDNSAnnouncer::shutdown(){
    for(auto p : probing){
        if (p->s == ProbeState::ANNOUNCED)
        {
            std::shared_ptr<DNSRecord> goodbye_record = INETDNS::copyDnsRecord(p->r);
            goodbye_record->ttl = 0;
            response_scheduler->post(goodbye_record, 0, NULL, 1);
        }
        // delete the probe and related time events
        timeEventSet->removeTimeEvent(p->e);
        freeDnsRecord(p->r);
        delete p->e;
        p.reset();
    }

    probing.clear();
}

void MDNSAnnouncer::elapse(INETDNS::TimeEvent* e, std::shared_ptr<void> data)
{
    std::shared_ptr<Probe> p = std::static_pointer_cast < Probe > (data);
    simtime_t tv;
    // no probe has been sent out so far..
    if (p->s == ProbeState::STARTING)
    {
        // do the first probe
        p->n_iter++;
        probe_scheduler->post(p->r, 0);
        p->s = ProbeState::PROBING;

        // 250msec delay
        tv = simTime() + STR_SIMTIME("250ms");
        timeEventSet->updateTimeEvent(p->e, tv);

    }
    else if (p->s == ProbeState::PROBING)
    {
        if (p->n_iter > 2)
        {
            // we're finished probing, start announcing
            // send first response for probe
            p->n_iter = 1;
            p->s = ProbeState::ANNOUNCING;
            response_scheduler->post(p->r, 1, NULL, 0);

            // add 2^(p->n_iter - 1) * 1s delay
            tv = simTime() + ((int) pow(2, (p->n_iter - 1)) * STR_SIMTIME("1s"));
            timeEventSet->updateTimeEvent(p->e, tv);
        }
        else
        {
            // still need to send out some probes
            p->n_iter++;
            probe_scheduler->post(p->r, 0);
            // 250msec delay
            tv = simTime() + STR_SIMTIME("250ms");
            timeEventSet->updateTimeEvent(p->e, tv);
        }
    }
    else if (p->s == ProbeState::ANNOUNCING)
    {
        if (p->n_iter > 3)
        {
            if (s == AnnouncerState::START || s == AnnouncerState::RESTART)
            {
                s = AnnouncerState::PROBE;
                initialize();
            }
            else if (s == AnnouncerState::PROBE && num_announced_jobs >= probing.size())
            {
                s = AnnouncerState::FINISHED;
            }

            if (p->s != ProbeState::ANNOUNCED)
            {
                num_announced_jobs++;
                p->s = ProbeState::ANNOUNCED;
                p->n_iter = 0;
            }
            // add record to cache..

            auth_cache->put_into_cache(p->r); // using the cache, we know when the record is up for eviction
            std::string hash = p->r->rname + std::string(":") + std::string(getTypeStringForValue(p->r->rtype))
                    + std::string(":") + std::string(getClassStringForValue(p->r->rclass));
            probe_to_cache[p->probe_id] = hash;

            // add 2^(p->n_iter - 1) * 1s delay
            tv = simTime() + (((int) pow(2, (p->n_iter - 1)) * STR_SIMTIME("1s")));
            timeEventSet->updateTimeEvent(p->e, tv);
        }
        else
        {
            // still have to send out annoucements
            p->n_iter++;
            response_scheduler->post(p->r, 1, NULL, 0);

            // add 2^(p->n_iter - 1) * 1s delay
            tv = simTime() + (((int) pow(2, (p->n_iter - 1)) * STR_SIMTIME("1s")));
            timeEventSet->updateTimeEvent(p->e, tv);
        }
    }
    else if (p->s == ProbeState::ANNOUNCED)
    {
        // don't put into cache, but send a response every 2^n s with max 60 min.
        p->n_iter++;
        response_scheduler->post(p->r, 1, NULL, 0);

        // add 2^(p->n_iter - 1) * 1s delay
        int scnds = ((int) pow(2, (p->n_iter - 1)));
        if (scnds > 3600)
            tv = simTime() + (3600 * STR_SIMTIME("1s"));
        else
            tv = simTime() + (scnds * STR_SIMTIME("1s"));
        timeEventSet->updateTimeEvent(p->e, tv);
    }
}

} /* namespace ODnsExtension */
