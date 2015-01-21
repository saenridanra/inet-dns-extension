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


#ifndef MDNSPROBESCHEDULER_H_
#define MDNSPROBESCHEDULER_H_

#include <omnetpp.h>
#include <TimeEventSet.h>
#include <UDPSocket.h>
#include <IPvXAddress.h>
#include <IPvXAddressResolver.h>
#include <DNS.h>
#include <DNSCache.h>
#include <DNSTTLCache.h>
#include <MDNS.h>
#include <glib.h>

namespace ODnsExtension {

#define MDNS_PROBE_WAIT 250 // wait 250ms, if no response, go to next state

typedef struct MDNSProbeJob{
    unsigned int id;
    ODnsExtension::TimeEvent* e;
    ODnsExtension::DNSRecord* r; // we probe for records,
    // see if they are already taken..
    int done;

    // when the job has to be performed.
    simtime_t delivery;

} probe_job;


class MDNSProbeScheduler
{
    protected:
        ODnsExtension::TimeEventSet* timeEventSet;
        GList* jobs;
        GList* history;

        UDPSocket* outSock; // socket on which to send the data via multicast...

        ODnsExtension::DNSTTLCache* cache; // cache reference

        unsigned int id_count = 0;

        virtual ODnsExtension::MDNSProbeJob* new_job(ODnsExtension::DNSRecord* r);
        virtual ODnsExtension::MDNSProbeJob* find_job(ODnsExtension::DNSRecord* r);
        virtual ODnsExtension::MDNSProbeJob* find_history(ODnsExtension::DNSRecord* r);
        virtual void done(ODnsExtension::MDNSProbeJob* pj);
        virtual void remove_job(ODnsExtension::MDNSProbeJob* pj);
        virtual int preparePacketAndSend(GList* qlist, GList* nslist, int qdcount, int nscount, int packetSize, int TC);

        virtual int append_question(ODnsExtension::MDNSProbeJob* pj, GList** qlist, GList** nslist, int *packetSize, int* qdcount, int* nscount);
    public:
        MDNSProbeScheduler(ODnsExtension::TimeEventSet* _timeEventSet);
        virtual ~MDNSProbeScheduler();

        static void elapseCallback(ODnsExtension::TimeEvent* e, void* data, void* thispointer);
        virtual void post(ODnsExtension::DNSRecord* r, int immediately);
        virtual void elapse(ODnsExtension::TimeEvent* e, void* data);

        virtual void setSocket(UDPSocket* sock){
            outSock = sock;
        }
        virtual void setCache(ODnsExtension::DNSTTLCache* _cache){
            cache = _cache;
        }
};

} /* namespace ODnsExtension */

#endif /* MDNSPROBESCHEDULER_H_ */
