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

#ifndef __OPP_DNS_EXTENSION_DNSCLIENT_H_
#define __OPP_DNS_EXTENSION_DNSCLIENT_H_

#include <omnetpp.h>

#include "UDPSocket.h"
#include "IPvXAddressResolver.h"
#include <vector>

#include "../utils/DNSTools.h"
#include "glib.h"
#include "glib/gprintf.h"

#include "../common/DNSCache.h"
#include "../common/DNSSimpleCache.h"

/**
 * @brief DNSClient provides dns functionality from a
 * client point-of-view. The app provides the possibility
 * to send DNS Queries to a DNS Name Server / Proxy or
 * DNS Cache.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 */
class DNSClient : public cSimpleModule
{
  protected:
    // Address vectors for known DNS servers
    std::vector<IPvXAddress> dns_servers;
    GHashTable *queries;
    GHashTable *callbacks;
    GHashTable *callback_handles;

    ODnsExtension::DNSCache* cache;

    int query_count;



    // Socket over which DNS queries are sent/received
    UDPSocket out;

    virtual void initialize(int stage);
    virtual int numInitStages() const { return 4; }
    virtual void handleMessage(cMessage *msg);
    virtual IPvXAddress* getAddressFromCache(char* dns_name);
    virtual int resolve(char* dns_name, int qtype, int primary, void (* callback) (int, void*), int id, void * handle);

  public:

};

#endif
