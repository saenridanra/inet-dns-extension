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

#ifndef MDNSRESPONSESCHEDULER_H_
#define MDNSRESPONSESCHEDULER_H_

#include <omnetpp.h>
#include <TimeEventSet.h>
#include <UDPSocket.h>
#include <IPvXAddress.h>
#include <IPvXAddressResolver.h>
#include <DNS.h>
#include <DNSCache.h>
#include <DNSSimpleCache.h>
#include <DNSTTLCache.h>
#include <MDNS.h>
#include <MDNS_Privacy.h>

#include <vector>
#include <unordered_map>
#include <memory>
#include <algorithm>

namespace ODnsExtension {

typedef struct MDNSResponseJob {
    unsigned int id;
    TimeEvent* e;
    std::shared_ptr<DNSRecord> r;

    IPvXAddress* querier;

    int done;
    int suppressed;
    int flush_cache;

    // when the job has to be performed.
    simtime_t delivery;

    MDNSResponseJob() :
            id(0), e(NULL), r(NULL), querier(NULL), done(0), suppressed(0), flush_cache(
                    0) {
    }
    ;

} mdns_response_job;

class MDNSResponseScheduler {
protected:
    void* resolver;
    TimeEventSet* timeEventSet;
    std::vector<std::shared_ptr<MDNSResponseJob>> jobs;
    std::vector<std::shared_ptr<MDNSResponseJob>> history;
    std::vector<std::shared_ptr<MDNSResponseJob>> suppressed;

    UDPSocket* outSock; // socket on which to send the data via multicast...
    UDPSocket* privacySock;
    IPvXAddress multicast_address = IPvXAddressResolver().resolve("225.0.0.1");

    std::unordered_map<std::string, std::shared_ptr<PrivateMDNSService>> *private_service_table;
    std::unordered_map<std::string, std::shared_ptr<FriendData>> *friend_data_table;
    std::unordered_map<std::string, std::shared_ptr<FriendData>> *instance_name_table;
    int hasPrivacy = 0;

    DNSTTLCache* auth_cache; // cached auth records for aux walks

    unsigned int id_count = 0;

    void (*callback)(std::shared_ptr<void>, void*);

    virtual std::shared_ptr<MDNSResponseJob> new_job(
            std::shared_ptr<DNSRecord> r, int done, int suppress);
    virtual std::shared_ptr<MDNSResponseJob> find_job(
            std::shared_ptr<DNSRecord> r);
    virtual std::shared_ptr<MDNSResponseJob> find_history(
            std::shared_ptr<DNSRecord> r);
    virtual std::shared_ptr<MDNSResponseJob> find_suppressed(
            std::shared_ptr<DNSRecord> r, IPvXAddress* querier);
    virtual void done(std::shared_ptr<MDNSResponseJob> rj);
    virtual void remove_job(std::shared_ptr<MDNSResponseJob> rj);
    virtual int appendTransitiveEntries(std::shared_ptr<DNSRecord> r,
            std::list<std::shared_ptr<DNSRecord>> *anlist, int* packetSize,
            int* ancount);
    virtual int appendFromCache(std::string hash,
            std::list<std::shared_ptr<DNSRecord>> *anlist, int* packetSize,
            int* ancount);
    virtual int appendRecord(std::shared_ptr<DNSRecord> r,
            std::list<std::shared_ptr<DNSRecord>> *anlist, int* packetSize,
            int* ancount);
    virtual int preparePacketAndSend(
            std::list<std::shared_ptr<DNSRecord>> anlist, int ancount,
            int packetSize, int is_private);
public:
    MDNSResponseScheduler(TimeEventSet* _timeEventSet, UDPSocket* _outSock,
            void* resolver);
    virtual ~MDNSResponseScheduler();

    static void elapseCallback(TimeEvent* e, std::shared_ptr<void> data, void* thispointer);
    virtual void post(std::shared_ptr<DNSRecord> r, int flush_cache,
            IPvXAddress* querier, int immediately);
    virtual void elapse(TimeEvent* e, std::shared_ptr<void> data);
    virtual void check_dup(std::shared_ptr<DNSRecord> r, int flush_cache);
    virtual void suppress(std::shared_ptr<DNSRecord> r, int flush_cache,
            IPvXAddress* querier, int immediately);

    void setCallback(void (_callback)(std::shared_ptr<void>, void*)) {
        callback = _callback;
    }

    virtual void setSocket(UDPSocket* sock) {
        outSock = sock;
    }
    virtual void setCache(DNSTTLCache* _cache) {
        auth_cache = _cache;
    }
    virtual void setAuthCache(DNSTTLCache* _cache) {
        auth_cache = _cache;
    }

    virtual void setPrivacyData(
            std::unordered_map<std::string, std::shared_ptr<PrivateMDNSService>>* private_service_table,
            std::unordered_map<std::string, std::shared_ptr<FriendData>>* friend_data_table,
            std::unordered_map<std::string, std::shared_ptr<FriendData>>* instance_name_table,
            UDPSocket* privacySocket) {
        this->private_service_table = private_service_table;
        this->friend_data_table = friend_data_table;
        this->instance_name_table = instance_name_table;
        this->privacySock = privacySocket;
        hasPrivacy = 1;
    }
};

#define MDNS_RESPONSE_ON_PROBE 250 // for probes we only wait up to 250ms
#define MDNS_RESPONSE_WAIT 500 // wait up to 500 msec, + some random delay..

} /* namespace ODnsExtension */

#endif /* MDNSRESPONSESCHEDULER_H_ */
