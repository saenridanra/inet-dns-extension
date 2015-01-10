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

Define_Module(DNSServerBase);

void DNSServerBase::initialize()
{
    cSimpleModule::initialize();
    // Initialize gates
    //in.setOutputGate(gate("udpIn"));
    out.setOutputGate(gate("udpOut"));
    out.bind(DNS_PORT);

    receivedQueries = 0;
}

void DNSServerBase::handleMessage(cMessage *msg)
{
    int isDNS = 0;
    int isQR = 0;
    ODnsExtension::Query* query;
    DNSPacket* response;

    // Check if we received a query
    if(msg->arrivedOn("udpIn")){
        if ((isDNS = ODnsExtension::isDNSpacket((cPacket*) msg)) && (isQR =
                    ODnsExtension::isQueryOrResponse((cPacket*) msg)) == 0) {
            query = ODnsExtension::resolveQuery((cPacket*) msg);
            receivedQueries++;

            response = handleQuery(query);

            // TODO: Find out how to get the source address
            // and send the response to the source address

            cPacket *pk = check_and_cast<cPacket *>(msg);
            UDPDataIndication *ctrl = check_and_cast<UDPDataIndication *>(pk->getControlInfo());
            IPvXAddress srcAddress = ctrl->getSrcAddr();
            sendResponse(response, srcAddress);
        }

    }
    else{
        delete msg;
    }

}

DNSPacket* DNSServerBase::handleQuery(ODnsExtension::Query* query){
    return NULL;
}

void DNSServerBase::sendResponse(DNSPacket *response, IPvXAddress returnAddress){
    out.sendTo(response, returnAddress, DNS_PORT);
}

DNSPacket* DNSServerBase::unsupportedOperation(ODnsExtension::Query *q){
    // TODO: return unsupported packet.
    return NULL;
}
