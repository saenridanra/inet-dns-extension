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
 * @brief @ref DNSEchoServer is a basic implementation of the DNSEchoServer needed for stateless DNS.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class DNSEchoServer : public cSimpleModule
{
  protected:
    /**
     * @brief Strings uniquely identifying this servers name and ip address.
     *
     * Which is needed for stateless dns resolving, as a response is generated based on this
     * data.
     */
    std::string nameserver, nameserver_ip;

    /**
     * @brief Received query counter variable
     */
    int receivedQueries = 0;

    /**
     * @brief Generated response counter variable.
     */
    int response_count = 0;

    /**
     * @brief Socket over which DNS queries are sent/received
     */
    UDPSocket out;

    virtual void initialize(int stage);
    virtual int numInitStages() const { return 4; }
    virtual void handleMessage(cMessage *msg);

    /**
     * @brief Creates an unsupported operation packet to be send to the querier.
     * @param q the query received from the querier
     * @return
     *      newly created unsupported operation packet
     */
    virtual DNSPacket* unsupportedOperation(std::shared_ptr<ODnsExtension::Query> q);

    /**
     * @brief This method sends a previously generated @ref DNSPacket to a receiver.
     * @param response the @ref DNSPacket that needs to be sent to the @ref IPvXAddress @p returnAddress.
     */
    virtual void sendResponse(DNSPacket *response, IPvXAddress returnAddress);

    /**
     * @brief Handles a query in a stateless DNS fashion.
     *
     * @param query The query that has to be handled.
     * @return A @ref DNSPacket that is sent by this server to the querier.
     */
    virtual DNSPacket* handleQuery(std::shared_ptr<ODnsExtension::Query> query);
};

#endif
