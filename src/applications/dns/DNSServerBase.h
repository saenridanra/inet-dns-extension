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

#ifndef __INETDNS_DNSSERVERBASE_H_
#define __INETDNS_DNSSERVERBASE_H_

#include <omnetpp.h>

#include "INETDefs.h"
#include "UDPSocket.h"
#include "UDPControlInfo_m.h"
#include "IPvXAddressResolver.h"
#include "DNSCache.h"
#include "DNSTools.h"
#include "DNS.h"

#include <memory>
#include <vector>
#include "list"
#include "unordered_map"


namespace INETDNS{
/**
 * @brief @ref CachedQuery structure
 *
 * Includes the original query packet and the src address
 * as a char string referenced by the internally assigned id.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct CachedQuery{
    /**
     * @brief unique id identifying the cached query.
     */
    int internal_id;

    /**
     * @brief Smart Pointer to the actual query.
     */
    std::shared_ptr<INETDNS::Query> query;

    CachedQuery(): internal_id(0) {};
} cached_query;
}

/**
 * @brief @ref DNSServerBase provides basic functionality for DNSServers used within this framework.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class DNSServerBase : public cSimpleModule
{
  protected:
    /**
     * @brief Variable counting how many queries have been received.
     */
    int receivedQueries;

    /**
     * @brief A unique running id that maps queries
     *
     * , so that they can be found when resolving recursively.
     */
    int internal_query_id = 0;

    /**
     * @brief A cache that maps internal_query_id to queries
     *
     * , so that they can be resolved recursively.
     */
    std::unordered_map<int, std::shared_ptr<INETDNS::CachedQuery>> queryCache;

    /**
     * @brief Cached responses from other name servers
     *
     * , s.t. the server does not need to query recursively if a valid record is still available.
     */
    INETDNS::DNSCache* responseCache;

    /**
     * The @ref IPvXAddresses of the rootServers within the network.
     *
     * If no root servers are available, recursive resolving does not work.
     */
    std::vector<IPvXAddress> rootServers;

    /**
     * @brief Socket over which DNS queries are sent/received
     */
    UDPSocket out;

  public:
    virtual void initialize(int stage);
    virtual int numInitStages() const { return 4; }
    virtual void handleMessage(cMessage *msg);

    /**
     * @brief Creates an unsupported operation packet to be send to the querier.
     * @param q the query received from the querier
     * @return
     *      newly created unsupported operation packet
     */
    virtual DNSPacket* unsupportedOperation(std::shared_ptr<INETDNS::Query> q);

    /**
     * @brief This method sends a previously generated @ref DNSPacket to a receiver.
     * @param response the @ref DNSPacket that needs to be sent to the @ref IPvXAddress @p returnAddress.
     */
    virtual void sendResponse(DNSPacket *response, IPvXAddress returnAddress);

    /**
     * @brief This method should be overwritten by the implementor.
     *
     * @param query The query that has to be handled.
     * @return A @ref DNSPacket that is sent by this server to the querier. When NULL the @ref DNSServerBase
     * assumes recursive resolving has been intiated and caches the query for further processing.
     */
    virtual DNSPacket* handleQuery(std::shared_ptr<INETDNS::Query> query);

    /**
     * @brief When receiving a response this method is called
     *
     * since it is assumed, that a recursive resolving process has been
     * initiated, which is why the server received a response.
     *
     * @param packet The @ref DNSPacket received from another server.
     * @return NULL, if further recursive resolving needs to be performed,
     * a packet for the original querier, otherwise.
     */
    virtual DNSPacket* handleRecursion(DNSPacket* packet);

    /**
     * @brief Store queries in the cache for recursive resolving.
     *
     * This method needs to be called, whenever recursive resolving is
     * initiated from implementors of this class.
     *
     * @param id Unique id identifying the query
     * @param query The original query, that needs to be remembered until the query has been resolved.
     *
     * @return 1 if successful, 0 otherwise.
     */
    int store_in_query_cache(int id, std::shared_ptr<INETDNS::Query> query);

    /**
     * @brief Creates a unique id for recursive resolving.
     * @return unique id
     */
    int getIdAndInc(){return internal_query_id++;}

    /**
     * @brief remove @ref CacheQuery from the cache
     *
     * Is called automatically after recursive resolving has finished.
     *
     * @param id unique id, identifying the query.
     * @param cq the @ref CachedQuery that needs to be removed
     */
    int remove_query_from_cache(int id, std::shared_ptr<INETDNS::CachedQuery> cq);

    /**
     * @brief Retrieve a @ref CachedQuery from the cache.
     *
     * @param id unique id identifying the @ref CachedQuery .
     *
     * @return Smart pointer to the @ref CachedQuery
     */
    std::shared_ptr<INETDNS::CachedQuery> get_query_from_cache(int id);

};

#endif
