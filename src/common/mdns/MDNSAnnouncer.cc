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

void MDNSAnnouncer::initialize(){
    // add host probes, i.e. hostname.local A, AAAA record
    if(s == AnnouncerState::STARTING_HOSTNAME){
        DNSRecord* a_record = (DNSRecord*) malloc(sizeof(a_record));
        DNSRecord* aaaa_record = (DNSRecord*) malloc(sizeof(aaaa_record));
        DNSRecord* a_ptr_record = (DNSRecord*) malloc(sizeof(a_ptr_record));
        DNSRecord* aaaa_ptr_record = (DNSRecord*) malloc(sizeof(aaaa_ptr_record));

        // populate records
        target = g_strdup_printf("%s.local", hostname);
        a_record->rname = g_strdup(target);
        a_record->rtype = DNS_TYPE_VALUE_A;
        a_record->rclass = DNS_CLASS_IN;
        a_record->rdata = g_strdup(hostaddress->get4().str().c_str()); // actual host address
        a_record->rdlength = strlen(hostaddress->get4().str().c_str());

        aaaa_record->rname = g_strdup(target);
        aaaa_record->rtype = DNS_TYPE_VALUE_AAAA;
        aaaa_record->rclass = DNS_CLASS_IN;
        aaaa_record->rdata = g_strdup(hostaddress->get6().str().c_str()); // actual host address
        aaaa_record->rdlength = strlen(hostaddress->get6().str().c_str());

        // generate inverse records as well
        a_ptr_record->rname = g_strdup_printf("%s.in-addr.arpa.", hostaddress->get4().str().c_str());
        a_ptr_record->rtype = DNS_TYPE_VALUE_PTR;
        a_ptr_record->rclass = DNS_CLASS_IN;
        a_ptr_record->rdata = g_strdup(target);
        a_ptr_record->rdlength = sizeof(target) - 1;

        aaaa_ptr_record->rname = g_strdup_printf("%s.ip6.arpa.", hostaddress->get6().str().c_str());
        aaaa_ptr_record->rtype = DNS_TYPE_VALUE_PTR;
        aaaa_ptr_record->rclass = DNS_CLASS_IN;
        aaaa_ptr_record->rdata = g_strdup(target);
        aaaa_ptr_record->rdlength = sizeof(target) - 1;

        // now add records to the list, create a time out, that is soon scheduled

        Probe* a = (Probe*) malloc(sizeof(a));
        Probe* a_ptr = (Probe*) malloc(sizeof(a_ptr));
        Probe* aaaa = (Probe*) malloc(sizeof(aaaa));
        Probe* aaaa_ptr = (Probe*) malloc(sizeof(aaaa_ptr));

        a->n_iter = 0;
        a->r = a_record;
        a->s = ProbeState::STARTING;
        a_ptr->n_iter = 0;
        a_ptr->r = a_ptr_record;
        a_ptr->s = ProbeState::STARTING;

        aaaa_ptr->n_iter = 0;
        aaaa_ptr->r = aaaa_record;
        aaaa_ptr->s = ProbeState::STARTING;
        aaaa_ptr->n_iter = 0;
        aaaa_ptr->r = aaaa_record;
        aaaa_ptr->s = ProbeState::STARTING;

        starting = g_list_append(starting, a);
        starting = g_list_append(starting, aaaa);
        starting = g_list_append(starting, a_ptr);
        starting = g_list_append(starting, aaaa_ptr);

        simtime_t tv = simTime() + STR_SIMTIME("20ms");

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(NULL);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSAnnouncer::elapseCallback);

    }
    else if(s == AnnouncerState::STARTING_SERVICES){
        // add service probes
        GList* next = g_list_first(to_announce);

        // add entries to the starting list and create a timeout event, so the callback is performed..
        while(next){
            MDNSService* s = (MDNSService*) next->data;
            add_service(s);
            next = g_list_next(next);
        }
    }
}

void MDNSAnnouncer::restart(){

}

void MDNSAnnouncer::add_service(MDNSService* service){

    // Create an SRV record for the service
    DNSRecord* service_record = (DNSRecord*) malloc(sizeof(service_record));
    char* label = g_strdup_printf("%s.%s", service->name, service->service_type);

    service_record->rname = g_strdup(label);
    service_record->rtype = DNS_TYPE_VALUE_SRV;
    service_record->rclass = DNS_CLASS_IN;
    service_record->rdata = target;

    Probe* p = (Probe*) malloc(sizeof(p));
    p->n_iter = 0;
    p->r = service_record;
    p->s = ProbeState::STARTING;

    starting = g_list_append(starting, p);
}

int  MDNSAnnouncer::check_conflict(DNSRecord* r){
    if(s == AnnouncerState::PROBING_HOSTNAME){

    }
    else if(s == AnnouncerState::PROBING_SERVICES){

    }
    else if(s == AnnouncerState::FINISHED){
        // check if we need to tell the other host
        // that we own the service instance, if so
        // schedule an immediate response
    }
    else{
        // this should not bother us at this moment
    }
    return 0;
}

void MDNSAnnouncer::elapse(ODnsExtension::TimeEvent* e, void* data){
    if(s == AnnouncerState::STARTING_HOSTNAME){

    }
    else if(s == AnnouncerState::PROBING_HOSTNAME){

    }
    else if(s == AnnouncerState::ANNOUNCING_HOSTNAME){

    }
    else if(s == AnnouncerState::STARTING_SERVICES){

    }
    else if(s == AnnouncerState::PROBING_SERVICES){

    }
    else if(s == AnnouncerState::ANNOUNCING_SERVICES){

    }
    else if(s == AnnouncerState::FINISHED){

    }
}

} /* namespace ODnsExtension */
