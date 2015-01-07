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

#include "DNSServerBase.h"

//Define_Module(DNSServerBase); // why does this not work? check if it makes a difference

void DNSServerBase::initialize()
{
    // Initialize gates
    out.setOutputGate(gate("udpOut"));
    in.setOutputGate(gate("udpIn"));
    in.bind(DNS_PORT);

    receivedQueries = 0;
}

void DNSServerBase::handleMessage(cMessage *msg)
{
    int isDNS = 0;
    int isQR = 0;
    ODnsExtension::Query* query;
    sddsadc

    // Check if we received a query
    if(msg->arrivedOn("udpIn")){
        if ((isDNS = ODnsExtension::isDNSpacket((cPacket*) msg)) && (isQR =
                    ODnsExtension::isQueryOrResponse((cPacket*) msg)) == 0) {
            query = ODnsExtension::resolveQuery((cPacket*) msg);
            receivedQueries++;

            response = handleQuery(query);

            // TODO: Find out how to get the source address
            // and send the response to the source address
        }

    }

}

void sendResponse(DNSPacket *response, IPvXAddress returnAddress){
    // TODO: send response
}

DNSPacket* DNSServerBase::unsupportedOperation(ODnsExtension::Query *q){
    // TODO: return unsupported packet.
    return NULL;
}
