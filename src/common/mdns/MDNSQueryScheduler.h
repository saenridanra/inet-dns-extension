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

#ifndef MDNSQUERYSCHEDULER_H_
#define MDNSQUERYSCHEDULER_H_

#include <omnetpp.h>
#include <TimeEventSet.h>
#include <UDPSocket.h>
#include <IPvXAddress.h>
#include <IPvXAddressResolver.h>
#include <DNS.h>
#include <DNSCache.h>
#include <DNSTTLCache.h>
#include <MDNS.h>
#include <MDNS_Privacy.h>
#include <vector>
#include <unordered_map>
#include <algorithm>

namespace ODnsExtension {

/**
 * @brief Structure holding information for response jobs.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct MDNSQueryJob {

    /**
     * @brief unique id of the probe job.
     */
    unsigned int id;

    /**
     * @brief The time event for this probe job.
     */
    ODnsExtension::TimeEvent* e;

    /**
     * @brief The key that needs to be queried
     */
    std::shared_ptr<ODnsExtension::MDNSKey> key;

    /**
     * @brief Whether the probe job is done or not.
     */
    int done;

    /**
     * @brief The time of delivery.
     */
    simtime_t delivery;

    MDNSQueryJob() :
            id(0), e(NULL), key(NULL), done(0), delivery(0) {
    }
    ;

} query_job;

/**
 * @brief This class schedules queries.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class MDNSQueryScheduler {
protected:
    /**
     * @brief Pointer to the resolver.
     */
    void* resolver;

    /**
     * @brief The time event set that performs elapsed events.
     */
    ODnsExtension::TimeEventSet* timeEventSet;

    /**
     * @brief A list of active jobs.
     */
    std::vector<std::shared_ptr<MDNSQueryJob>> jobs;

    /**
     * @brief A list of jobs already finished.
     */
    std::vector<std::shared_ptr<MDNSQueryJob>> history;

    /**
     * @brief Socket over which DNS queries are sent/received.
     */
    UDPSocket outSock;

    /**
     * @brief Socket over which private DNS queries are sent/received.
     */
    UDPSocket privacySock;

    /**
     * @brief Local multicast address in use.
     */
    IPvXAddress multicast_address = IPvXAddressResolver().resolve("225.0.0.1");


    /**
     * @brief A map from strings (service types) to @ref ODnsExtension::PrivateMDNSService .
     */
    std::unordered_map<std::string, std::shared_ptr<ODnsExtension::PrivateMDNSService>> *private_service_table;

    /**
     * @brief A map from strings (friend ids) to @ref ODnsExtension::FriendData .
     */
    std::unordered_map<std::string, std::shared_ptr<ODnsExtension::FriendData>> *friend_data_table;

    /**
     * @brief A map from strings (instance names) to @ref ODnsExtension::FriendData .
     */
    std::unordered_map<std::string, std::shared_ptr<ODnsExtension::FriendData>> *instance_name_table;

    /**
     * @brief Whether privacy extenstion is active.
     */
    int hasPrivacy = 0;

    /**
     * @brief A cache used for caching announced services.
     */
    DNSTTLCache* cache;

    /**
     * @brief Running variable for unique ids
     */
    unsigned int id_count = 0;

    /**
     * @brief Callback that is called when an event is due.
     */
    void (*callback)(std::shared_ptr<void>, void*);

    /**
     * @brief Creates a new @ref MDNSQueryJob
     * @param key Key for which a job should be created.
     * @return Smart pointer to newly created probe job.
     */
    virtual std::shared_ptr<ODnsExtension::MDNSQueryJob> new_job(
            std::shared_ptr<ODnsExtension::MDNSKey> key);

    /**
     * @brief Finds a job in the active list
     * @param key Key which needs to be found
     * @return Smart pointer to the job.
     */
    virtual std::shared_ptr<ODnsExtension::MDNSQueryJob> find_job(
            std::shared_ptr<ODnsExtension::MDNSKey> key);

    /**
     * @brief Finds a job in the history list
     * @param key Key which needs to be found
     * @return Smart pointer to the job.
     */
    virtual std::shared_ptr<ODnsExtension::MDNSQueryJob> find_history(
            std::shared_ptr<ODnsExtension::MDNSKey> key);

    /**
     * @brief Marks a job as done and moves it to the history list.
     * @param qj Job that needs to be marked.
     */
    virtual void done(std::shared_ptr<ODnsExtension::MDNSQueryJob> qj);

    /**
     * @brief Removes a job completely.
     * @param qj Job that needs to be removed.
     */
    virtual void remove_job(std::shared_ptr<ODnsExtension::MDNSQueryJob> qj);

    /**
     * @brief Appends cached entried to a list.
     *
     * @param key The key for which the cache has to be searched.
     * @param list The list records need to be appended to.
     *
     * @return the list with appended entries
     */
    virtual std::list<std::shared_ptr<DNSRecord>> append_cache_entries(
            std::shared_ptr<MDNSKey> key,
            std::list<std::shared_ptr<DNSRecord>> list);

    /**
     * @brief Appends a question along with the already prepared questions.
     *
     * @param key The key for which a question and answer needs to be appended.
     * @param qlist The questions for this probe.
     * @param anlist The answer records in the probe.
     * @param qdcount The amount of questions.
     * @param ancount The amount of answer records.
     * @param packetSize The size of the packet.
     * @param TC Whether the packet was trunctated.
     * @param is_private Whether the packet is flagged private.
     *
     * @return 1 if successful, 0 otherwise
     */
    virtual int append_question(std::shared_ptr<MDNSKey> key,
            std::list<std::shared_ptr<DNSQuestion>>* qlist,
            std::list<std::shared_ptr<DNSRecord>>* anlist, int *packetSize,
            int* qdcount, int* ancount, int is_private);

    /**
     * @brief Prepares a packet and sends it via multicast.
     *
     * @param qlist The questions for this probe.
     * @param anlist The answer records in the probe.
     * @param nslist The authoritative records in the probe.
     * @param arlist The additional records in the probe.
     * @param qdcount The amount of questions.
     * @param ancount The amount of answer records.
     * @param nscount The amount of authoritative records.
     * @param arcount The amount of additional records.
     * @param packetSize The size of the packet.
     * @param TC Whether the packet was trunctated.
     * @param is_private Whether the packet is flagged private.
     *
     * @return 1 if successful, 0 otherwise
     */
    virtual int preparePacketAndSend(
            std::list<std::shared_ptr<DNSQuestion>> qlist,
            std::list<std::shared_ptr<DNSRecord>> anlist,
            std::list<std::shared_ptr<DNSRecord>> nslist,
            std::list<std::shared_ptr<DNSRecord>> arlist, int qdcount,
            int ancount, int nscount, int arcount, int packetSize, int TC,
            int is_private);

public:
    /**
     * @brief Constructor for @ref MDNSQueryScheduler
     *
     * @param _timeEventSet Pointer to the time event set, that the resolver uses.
     * @param _outSock Pointer to the socket the resolver uses.
     * @param resolver Pointer to the resolver itself.
     */
    MDNSQueryScheduler(ODnsExtension::TimeEventSet* _timeEventSet,
            UDPSocket* _outSock, void* resolver);
    virtual ~MDNSQueryScheduler();

    /**
     * @brief Static callback function, called when an event expires.
     *
     * @param e Event that triggered the callback.
     * @param data Smart pointer to void data, in this case @ref Probe
     * @param thispointer A reference to the handle that created the event.
     */
    static void elapseCallback(ODnsExtension::TimeEvent* e, std::shared_ptr<void> data,
            void* thispointer);

    /**
     * @brief Post a query using this method.
     *
     * @param key Key for which a query is generated.
     * @param immediately Whether the query needs to be sent immediately.
     */
    virtual void post(std::shared_ptr<ODnsExtension::MDNSKey> key,
            int immediately);

    /**
     * @brief Duplicate question suppression
     *
     * According to RFC 6762 <http://tools.ietf.org/html/rfc6762>, performs
     * duplicate question suppression
     *
     * @param key Key to check duplicates for.
     */
    virtual void check_dup(std::shared_ptr<ODnsExtension::MDNSKey> key);

    /**
     * @brief Elapse method, when the next scheduled event is due.
     *
     * @param e Event that triggered the elapse
     * @param data smart pointer to void data, in this case always @ref MDNSQueryJob
     */
    virtual void elapse(ODnsExtension::TimeEvent* e, std::shared_ptr<void> data);

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
    virtual void setCache(ODnsExtension::DNSTTLCache* _cache) {
        cache = _cache;
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
};

} /* namespace ODnsExtension */

#endif /* MDNSQUERYSCHEDULER_H_ */
