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

#ifndef __INETDNS_DNSCLIENT_H_
#define __INETDNS_DNSCLIENT_H_

#include <omnetpp.h>

#include "INETDefs.h"
#include "UDPSocket.h"
#include "L3AddressResolver.h"
#include <vector>

#include <iostream>
#include <unordered_map>
#include <string>
#include <memory>

#include "DNSTools.h"
#include "DNSCache.h"
#include "DNSSimpleCache.h"

/**
 * @brief @ref DNSClient provides dns functionality from a
 * client point-of-view.
 *
 * The app provides the possibility to send DNS Queries to a
 * DNS Name Server / Proxy or DNS Cache.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class DNSClient: public cSimpleModule {
protected:
    /**
     * @brief @ref inet::L3Address vector for known DNS servers
     */
    std::vector<inet::L3Address> dns_servers;

    /**
     * @brief This map manages queries currently waiting to be resolved
     */
    std::unordered_map<int, std::string> queries;
    /**
     * @brief This map maps callback functions to queries, so that
     * operations can be performed, once resolved.
     */
    std::unordered_map<int, void (*)(int, void*)> callbacks;
    /**
     * @brief This map contains the callback handles on which the
     * callback should be performed.
     */
    std::unordered_map<int, void*> callback_handles;

    /**
     * @brief A @ref DNSCache that is used to store resolved queries.
     */
    std::shared_ptr<INETDNS::DNSCache> cache;

    /**
     * @brief The overall query_count used for statistics.
     */
    int query_count;

    /**
     * @brief Socket over which DNS queries are sent/received
     */
    inet::UDPSocket out;

    virtual void initialize(int stage);
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void handleMessage(cMessage *msg);

    /**
     * @brief Get the records corresponding to the query name
     *
     * @param dns_name the record label as string
     *
     * @return
     *      returns list of records corresponding to the query.
     */
    virtual std::list<std::shared_ptr<DNSRecord>> getFromCache(std::string dns_name);

    /**
     * @brief Get the records corresponding to the query name
     *
     * @param id the query id
     *
     * @return
     *      returns list of records corresponding to the query.
     */
    virtual std::list<std::shared_ptr<DNSRecord>> getFromCacheByID(int id);

    /**
     * @brief This function is used to resolve a query using the
     * primary or secondary dns server.
     *
     * Once resolved a callback is called which is used to perform some function
     * on the response, for instance write statistics.
     *
     * @param dns_name the record label as string
     * @param qtype the dns type value of the record
     * @param primary whether it should be resolved using the primary dns server
     * @param callback the callback that is later used to operate on the response
     * @param id the unique id of the query, related to the query_count
     * @param handle the handle on which the operation should be performed on
     *
     * @return
     *      returns the query count, that is incremented if the method is successful.
     */
    virtual int resolve(std::string dns_name, int qtype, int primary,
            void (*callback)(int, void*), int id, void * handle);

};

#endif
