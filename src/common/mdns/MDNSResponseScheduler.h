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
#include <DNSTools.h>
#include <MDNS.h>
#include <MDNS_Privacy.h>
#include <SignalReceiver.h>

#include <vector>
#include <unordered_map>
#include <memory>
#include <algorithm>

namespace INETDNS {

/**
 * @brief Structure holding information for response jobs.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct MDNSResponseJob {

    /**
     * @brief unique id of the probe job.
     */
    unsigned int id;

    /**
     * @brief The time event for this probe job.
     */
    TimeEvent* e;

    /**
     * @brief The record that needs to be probed.
     */
    std::shared_ptr<DNSRecord> r;

    /**
     * @brief The address of the querier
     */
    IPvXAddress* querier;

    /**
     * @brief Whether the probe job is done or not.
     */
    int done;

    /**
     * @brief Whether the probe job is suppressed or not.
     */
    int suppressed;

    /**
     * @brief Whether cache flushing has to be performed when receiving this answer.
     */
    int flush_cache;

    /**
     * @brief The time of delivery.
     */
    simtime_t delivery;

    MDNSResponseJob() :
            id(0), e(NULL), r(NULL), querier(NULL), done(0), suppressed(0), flush_cache(
                    0) {
    }
    ;

} mdns_response_job;

/**
 * @brief This class schedules responses.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class MDNSResponseScheduler {
protected:
    /**
     * @brief Pointer to the resolver.
     */
    void* resolver;

    /**
     * @brief Reference to a signal receiver, we emit sending packets to
     */
    SignalReceiver* signalReceiver;

    /**
     * @brief The time event set that performs elapsed events.
     */
    INETDNS::TimeEventSet* timeEventSet;

    /**
     * @brief A list of active jobs.
     */
    std::vector<std::shared_ptr<MDNSResponseJob>> jobs;

    /**
     * @brief A list of jobs already finished.
     */
    std::vector<std::shared_ptr<MDNSResponseJob>> history;

    /**
     * @brief A list of suppressed jobs.
     */
    std::vector<std::shared_ptr<MDNSResponseJob>> suppressed;

    /**
     * @brief Socket over which DNS queries are sent/received.
     */
    UDPSocket* outSock;

    /**
     * @brief Socket over which private DNS queries are sent/received.
     */
    UDPSocket* privacySock;

    /**
     * @brief Local multicast address in use.
     */
    IPvXAddress multicast_address = IPvXAddressResolver().resolve("225.0.0.1");

    /**
     * @brief A map from strings (service types) to @ref ODnsExtension::PrivateMDNSService .
     */
    std::unordered_map<std::string, std::shared_ptr<INETDNS::PrivateMDNSService>> *private_service_table;

    /**
     * @brief A map from strings (friend ids) to @ref ODnsExtension::FriendData .
     */
    std::unordered_map<std::string, std::shared_ptr<INETDNS::FriendData>> *friend_data_table;

    /**
     * @brief A map from strings (instance names) to @ref ODnsExtension::FriendData .
     */
    std::unordered_map<std::string, std::shared_ptr<INETDNS::FriendData>> *instance_name_table;

    /**
     * @brief Whether privacy extenstion is active.
     */
    int hasPrivacy = 0;

    /**
     * @brief A cache used for caching announced services.
     */
    DNSTTLCache* auth_cache;

    /**
     * @brief Running variable for unique ids
     */
    unsigned int id_count = 0;

    /**
     * @brief Callback that is called when an event is due.
     */
    void (*callback)(std::shared_ptr<void>, void*);

    /**
     * @brief Creates a new @ref MDNSResponseJob
     * @param r Record for which a job needs to be created.
     * @param done Whether the record is already done
     * @param suppress Whether the job needs to be suppressed
     * @return Smart pointer to newly created response job.
     */
    virtual std::shared_ptr<MDNSResponseJob> new_job(
            std::shared_ptr<DNSRecord> r, int done, int suppress);

    /**
     * @brief Finds a job in the active list
     * @param r Record which needs to be found
     * @return Smart pointer to the job.
     */
    virtual std::shared_ptr<MDNSResponseJob> find_job(
            std::shared_ptr<DNSRecord> r);

    /**
     * @brief Finds a job in the history list
     * @param r Record which needs to be found
     * @return Smart pointer to the job.
     */
    virtual std::shared_ptr<MDNSResponseJob> find_history(
            std::shared_ptr<DNSRecord> r);

    /**
     * @brief Finds a job in the suppressed list
     * @param r Record which needs to be found
     * @return Smart pointer to the job.
     */
    virtual std::shared_ptr<MDNSResponseJob> find_suppressed(
            std::shared_ptr<DNSRecord> r, IPvXAddress* querier);

    /**
     * @brief Marks a job as done and moves it to the history list.
     * @param rj Job that needs to be marked.
     */
    virtual void done(std::shared_ptr<MDNSResponseJob> rj);

    /**
     * @brief Removes a job completely.
     * @param rj Job that needs to be removed.
     */
    virtual void remove_job(std::shared_ptr<MDNSResponseJob> rj);

    /**
     * @brief Appends transitive entries.
     *
     * This means, that if an SRV record has been appended,
     * the cache is checked for records this SRV record points to.
     *
     * @param r Record for which transitive entries may exist.
     * @param anlist The answer records in the response.
     * @param ancount The amount of answer records.
     * @param packetSize The size of the packet.
     *
     * @return 1 if successful, 0 otherwise
     */
    virtual int appendTransitiveEntries(std::shared_ptr<DNSRecord> r,
            std::list<std::shared_ptr<DNSRecord>> *anlist, int* packetSize,
            int* ancount);

    /**
     * @brief Given a hash, appends entries from the cache.
     *
     * @param hash A hash value for which cache entries may exist.
     * @param anlist The answer records in the response.
     * @param packetSize The size of the packet.
     * @param ancount The amount of answer records.
     *
     * @return 1 if successful, 0 otherwise
     */
    virtual int appendFromCache(std::string hash,
            std::list<std::shared_ptr<DNSRecord>> *anlist, int* packetSize,
            int* ancount);

    /**
     * @brief Appends a record to the list.
     *
     * @param r Record for which transitive entries may exist.
     * @param anlist The answer records in the response.
     * @param ancount The amount of answer records.
     * @param packetSize The size of the packet.
     *
     * @return 1 if successful, 0 otherwise
     */
    virtual int appendRecord(std::shared_ptr<DNSRecord> r,
            std::list<std::shared_ptr<DNSRecord>> *anlist, int* packetSize,
            int* ancount);

    /**
     * @brief Prepares a packet and sends it via multicast.
     *
     * @param anlist The answer records in the response.
     * @param ancount The amount of answer records.
     * @param packetSize The size of the packet.
     * @param is_private Whether the packet is flagged private.
     *
     * @return 1 if successful, 0 otherwise
     */
    virtual int preparePacketAndSend(
            std::list<std::shared_ptr<DNSRecord>> anlist, int ancount,
            int packetSize, int is_private);
public:
    /**
     * @brief Constructor for @ref MDNSResponseScheduler
     *
     * @param _timeEventSet Pointer to the time event set, that the resolver uses.
     * @param _outSock Pointer to the socket the resolver uses.
     * @param resolver Pointer to the resolver itself.
     */
    MDNSResponseScheduler(TimeEventSet* _timeEventSet, UDPSocket* _outSock,
            void* resolver);
    virtual ~MDNSResponseScheduler();

    /**
     * @brief Static callback function, called when an event expires.
     *
     * @param e Event that triggered the callback.
     * @param data Smart pointer to void data, in this case @ref Probe
     * @param thispointer A reference to the handle that created the event.
     */
    static void elapseCallback(TimeEvent* e, std::shared_ptr<void> data, void* thispointer);

    /**
     * @brief Post a response using this method.
     *
     * @param r Record for which a response is generated.
     * @param flush_cache Whether the cache of the querier needs to be flushed.
     * @param querier The address of the querier.
     * @param immediately Whether the response needs to be sent immediately.
     */
    virtual void post(std::shared_ptr<DNSRecord> r, int flush_cache,
            IPvXAddress* querier, int immediately);

    /**
     * @brief Elapse method, when the next scheduled event is due.
     *
     * @param e Event that triggered the elapse
     * @param data smart pointer to void data, in this case always @ref MDNSResponseJob
     */
    virtual void elapse(TimeEvent* e, std::shared_ptr<void> data);

    /**
     * @brief Duplicate answer suppression
     *
     * According to RFC 6762 <http://tools.ietf.org/html/rfc6762>, performs
     * duplicate answer suppression
     *
     * @param r record to check.
     * @param flush_cache whether cache needs to be flushed.
     */
    virtual void check_dup(std::shared_ptr<DNSRecord> r, int flush_cache);

    /**
     * @brief Suppresses a response once identified as duplicate.
     *
     * According to RFC 6762 <http://tools.ietf.org/html/rfc6762>, performs
     * duplicate answer suppression and schedules
     *
     * @param r record to suppress.
     * @param flush_cache whether cache needs to be flushed.
     * @param querier the querier the response originated from.
     * @param immediately whether this has to be done immediately.
     */
    virtual void suppress(std::shared_ptr<DNSRecord> r, int flush_cache,
            IPvXAddress* querier, int immediately);

    /**
     * @brief Set the callback method for this scheduler
     *
     * @param _callback The callback on which the scheduler operates.
     */
    void setCallback(void (_callback)(std::shared_ptr<void>, void*)) {
        callback = _callback;
    }

    /**
     * @brief The socket the scheduler uses to send data
     *
     * @param sock Set the output socket
     */
    virtual void setSocket(UDPSocket* sock) {
        outSock = sock;
    }

    /**
     * @brief The cache this scheduler uses
     *
     * @param _cache A pointer to the cache
     */
    virtual void setAuthCache(DNSTTLCache* _cache) {
        auth_cache = _cache;
    }

    /**
     * @brief Set the privacy information, i.e. services, friend data..
     *
     * @param private_service_table Table containing information about private services.
     * @param friend_data_table Table containing friend data.
     * @param instance_name_table Mapping of instance names to friend data.
     * @param privacySocket Set the output socket for output data
     */
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

    /**
     * @brief Set the signal receiver
     *
     * @param pSignalReceiver receiver this class uses to emit signals to
     */
    virtual void setSignalReceiver(SignalReceiver *pSignalReceiver){
        signalReceiver = pSignalReceiver;
    }
};

#define MDNS_RESPONSE_ON_PROBE 250 // for probes we only wait up to 250ms
#define MDNS_RESPONSE_WAIT 500 // wait up to 500 msec, + some random delay..

} /* namespace ODnsExtension */

#endif /* MDNSRESPONSESCHEDULER_H_ */
