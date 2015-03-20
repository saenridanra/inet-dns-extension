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

#ifndef __OPP_DNS_EXTENSION_DNSSERVERBASE_H_
#define __OPP_DNS_EXTENSION_DNSSERVERBASE_H_

#include <omnetpp.h>

#include "INETDefs.h"
#include "UDPSocket.h"
#include "UDPControlInfo_m.h" // to get teh src addr
#include "IPvXAddressResolver.h"
#include "DNSCache.h"
#include "DNSTools.h"
#include "DNS.h"
#include <vector>

#include "DNSTools.h"
#include "list"
#include "unordered_map"

/**
 * CachedQuery structure includes
 * the original query packet and the src address
 * as a char string referenced by the internally assigned id.
 */
typedef struct CachedQuery{
        int internal_id;
        ODnsExtension::Query* query;
} cached_query;

/**
 * @brief DNSServerBase provides basic functionality
 * for DNSServers used within this framework.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 */
class DNSServerBase : public cSimpleModule
{
  public:

  protected:
    int receivedQueries;

    int internal_query_id = 0;
    std::unordered_map<int, CachedQuery*> queryCache;
    ODnsExtension::DNSCache* responseCache;
    std::vector<IPvXAddress> rootServers;

    // Socket over which DNS queries are sent/received
    UDPSocket out;

  public:
    virtual void initialize(int stage);
    virtual int numInitStages() const { return 4; }
    virtual void handleMessage(cMessage *msg);
    virtual DNSPacket* unsupportedOperation(ODnsExtension::Query *q);
    virtual void sendResponse(DNSPacket *response, IPvXAddress returnAddress);
    virtual DNSPacket* handleQuery(ODnsExtension::Query *query);
    virtual DNSPacket* handleRecursion(DNSPacket* packet);
    int store_in_query_cache(int id, ODnsExtension::Query* query);
    int getIdAndInc(){return internal_query_id++;}
    int remove_query_from_cache(int id, CachedQuery* cq);
    CachedQuery* get_query_from_cache(int id);

};

#endif
