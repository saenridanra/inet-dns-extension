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

#ifndef MDNSANNOUNCER_H_
#define MDNSANNOUNCER_H_

#include <omnetpp.h>
#include <IPvXAddress.h>
#include <TimeEventSet.h>
#include <DNS.h>
#include <DNSCache.h>
#include <DNSTTLCache.h>
#include <MDNS.h>
#include <glib.h>
#include <glib/gprintf.h>

namespace ODnsExtension {

enum ProbeState{
    STARTING,
    PROBING,
    ANNOUNCING,
    ANNOUNCED
};

enum AnnouncerState{
    STARTING_HOSTNAME,
    PROBING_HOSTNAME,
    ANNOUNCING_HOSTNAME,
    STARTING_SERVICES,
    PROBING_SERVICES,
    ANNOUNCING_SERVICES,
    FINISHED
};

struct Probe{
        ODnsExtension::DNSRecord* r;
        int n_iter;
        ProbeState s;
};

class MDNSAnnouncer
{
    protected:
        ODnsExtension::TimeEventSet* timeEventSet;
        ODnsExtension::DNSTTLCache* auth_cache; // this cache is used for successfully
        IPvXAddress* hostaddress;
        char* hostname;
        char* target;
        GHashTable* serviceToCacheMap; // lookup of services in cache

        GList* to_announce; // this is a list consisting of MDNSService structs that have to be published

        GList* starting; // keep starting Probes here
        GList* probing;  // move them to probing list, when starting
        GList* annoucing;// move them to announcing list when probing is finished

        AnnouncerState s;

    public:
        MDNSAnnouncer(ODnsExtension::TimeEventSet* _timeEventSet, GList* services, char* _hostname, IPvXAddress* _hostaddress){
            timeEventSet = _timeEventSet;
            to_announce = services;
            hostname = _hostname;
            hostaddress = _hostaddress;
            s = AnnouncerState::STARTING_HOSTNAME;

            serviceToCacheMap = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        }
        virtual ~MDNSAnnouncer(){

        }

        virtual void initialize();
        virtual void restart();
        virtual int check_conflict(DNSRecord* r);
        virtual void add_service(MDNSService* service);
        virtual void elapse(ODnsExtension::TimeEvent* e, void* data);

        virtual ODnsExtension::DNSTTLCache* getCache(){
            return auth_cache;
        }

        static void elapseCallback(ODnsExtension::TimeEvent* e, void* data, void* thispointer){
            MDNSAnnouncer* self = static_cast<MDNSAnnouncer*>(thispointer);
            self->elapse(e, data);
        }
};

#define MDNS_PROBE_TIMEOUT 250 // timeout for probing

} /* namespace ODnsExtension */

#endif /* MDNSANNOUNCER_H_ */
