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
    if(s == AnnouncerState::STARTING){

    }
    else if(s == AnnouncerState::PROBING){
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

void add_service(MDNSService* service){

    // Create an SRV record for the service
    DNSRecord* service_record = (DNSRecord*) malloc(sizeof(service_record));
    char* label = g_strdup_printf("%s.%s", service->name, service->service_type);

    service_record->rname = g_strdup(label);
    service_record->rtype = DNS_TYPE_VALUE_SRV;
    service_record->rclass = DNS_CLASS_IN;
    service_record->rdata = target;
}

int  MDNSAnnouncer::check_conflict(DNSRecord* r){

}

void MDNSAnnouncer::elapse(ODnsExtension::TimeEvent* e, void* data){

}

} /* namespace ODnsExtension */
