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
#include <DNSTools.h>
#include <MDNS.h>
#include <MDNS_Privacy.h>
#include <SignalReceiver.h>

#include <vector>
#include <unordered_map>
#include <list>
#include <memory>
#include <algorithm>

namespace INETDNS {

#define MDNS_PROBE_WAIT 250 // wait 250ms, if no response, go to next state

/**
 * @brief Structure holding information for probe jobs.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct MDNSProbeJob {

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
    std::shared_ptr<DNSRecord> r; // we probe for records,

    /**
     * @brief Whether the probe job is done or not.
     */
    int done;

    /**
     * @brief The time of delivery.
     */
    simtime_t delivery;

    MDNSProbeJob() :
            id(0), e(NULL), r(NULL), done(0), delivery(0) {
    }
    ;

} probe_job;

/**
 * @brief This class schedules probes.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class MDNSProbeScheduler {
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
    TimeEventSet* timeEventSet;

    /**
     * @brief A list of active jobs.
     */
    std::vector<std::shared_ptr<MDNSProbeJob>> jobs;

    /**
     * @brief A list of jobs already finished.
     */
    std::vector<std::shared_ptr<MDNSProbeJob>> history;

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
     * @brief Creates a new @ref MDNSProbeJob
     * @param r Record for which a job needs to be created.
     * @return Smart pointer to newly created probe job.
     */
    virtual std::shared_ptr<MDNSProbeJob> new_job(
            std::shared_ptr<DNSRecord> r);

    /**
     * @brief Finds a job in the active list
     * @param r Record which needs to be found
     * @return Smart pointer to the job.
     */
    virtual std::shared_ptr<MDNSProbeJob> find_job(
            std::shared_ptr<DNSRecord> r);

    /**
     * @brief Finds a job in the history list
     * @param r Record which needs to be found
     * @return Smart pointer to the job.
     */
    virtual std::shared_ptr<MDNSProbeJob> find_history(
            std::shared_ptr<DNSRecord> r);

    /**
     * @brief Marks a job as done and moves it to the history list.
     * @param pj Job that needs to be marked.
     */
    virtual void done(std::shared_ptr<MDNSProbeJob> pj);

    /**
     * @brief Removes a job completely.
     * @param pj Job that needs to be removed.
     */
    virtual void remove_job(std::shared_ptr<MDNSProbeJob> pj);

    /**
     * @brief Prepares a packet and sends it via multicast.
     *
     * @param qlist The questions for this probe.
     * @param nslist The authoritative records in the probe.
     * @param qdcount The amount of questions.
     * @param nscount The amount of authoritative records.
     * @param packetSize The size of the packet.
     * @param TC Whether the packet was trunctated.
     * @param is_private Whether the packet is flagged private.
     *
     * @return 1 if successful, 0 otherwise
     */
    virtual int preparePacketAndSend(
            std::list<std::shared_ptr<DNSQuestion>> qlist,
            std::list<std::shared_ptr<DNSRecord>> nslist, int qdcount,
            int nscount, int packetSize, int TC, int is_private);

    /**
     * @brief Appends a question along with the already prepared questions.
     *
     * @param pj The probejob that needs to be appended
     * @param qlist The questions for this probe.
     * @param nslist The authoritative records in the probe.
     * @param qdcount The amount of questions.
     * @param nscount The amount of authoritative records.
     * @param packetSize The size of the packet.
     * @param TC Whether the packet was trunctated.
     * @param is_private Whether the packet is flagged private.
     *
     * @return 1 if successful, 0 otherwise
     */
    virtual int append_question(std::shared_ptr<MDNSProbeJob> pj,
            std::list<std::shared_ptr<DNSQuestion>>* qlist,
            std::list<std::shared_ptr<DNSRecord>>* nslist, int *packetSize,
            int* qdcount, int* nscount, int is_private);
public:
    /**
     * @brief Constructor for @ref MDNSProbeScheduler
     *
     * @param _timeEventSet Pointer to the time event set, that the resolver uses.
     * @param _outSock Pointer to the socket the resolver uses.
     * @param resolver Pointer to the resolver itself.
     */
    MDNSProbeScheduler(TimeEventSet* _timeEventSet,
            UDPSocket* _outSock, void* resolver);
    virtual ~MDNSProbeScheduler();

    /**
     * @brief Static callback function, called when an event expires.
     *
     * @param e Event that triggered the callback.
     * @param data Smart pointer to void data, in this case @ref Probe
     * @param thispointer A reference to the handle that created the event.
     */
    static void elapseCallback(TimeEvent* e, std::shared_ptr<void> data,
            void* thispointer);

    /**
     * @brief Post a probe using this method.
     *
     * @param r Record for which a probe is generated.
     * @param immediately Whether the probe needs to be sent immediately.
     */
    virtual void post(std::shared_ptr<DNSRecord> r,
            int immediately);

    /**
     * @brief Elapse method, when the next scheduled event is due.
     *
     * @param e Event that triggered the elapse
     * @param data smart pointer to void data, in this case always @ref MDNSProbeJob
     */
    virtual void elapse(TimeEvent* e, std::shared_ptr<void> data);

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
    virtual void setCache(DNSTTLCache* _cache) {
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

    /**
     * @brief Set the signal receiver
     *
     * @param pSignalReceiver receiver this class uses to emit signals to
     */
    virtual void setSignalReceiver(SignalReceiver *pSignalReceiver){
        signalReceiver = pSignalReceiver;
    }
};

} /* namespace ODnsExtension */

#endif /* MDNSPROBESCHEDULER_H_ */
