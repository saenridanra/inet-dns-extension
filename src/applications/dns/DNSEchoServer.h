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

#ifndef __OPP_DNS_EXTENSION_DNSECHOSERVER_H_
#define __OPP_DNS_EXTENSION_DNSECHOSERVER_H_

#include <omnetpp.h>

#include "INETDefs.h"
#include "UDPSocket.h"
#include "UDPControlInfo_m.h"
#include "IPvXAddressResolver.h"
#include "DNSCache.h"
#include "DNSTools.h"
#include "DNS.h"
#include <regex>
#include <vector>
#include <list>

#include "DNSTools.h"

/**
 * @brief DNSEchoServer
 *  Basic implementation of the DNSEchoServer needed for stateless DNS.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 */
class DNSEchoServer : public cSimpleModule
{
  protected:
    std::string nameserver, nameserver_ip;
    int receivedQueries = 0;
    int response_count = 0;

    // Socket over which DNS queries are sent/received
    UDPSocket out;

    virtual void initialize(int stage);
    virtual int numInitStages() const { return 4; }
    virtual void handleMessage(cMessage *msg);
    virtual DNSPacket* unsupportedOperation(std::shared_ptr<ODnsExtension::Query> q);
    virtual void sendResponse(DNSPacket *response, IPvXAddress returnAddress);
    virtual DNSPacket* handleQuery(std::shared_ptr<ODnsExtension::Query> query);
};

#endif
