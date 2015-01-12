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

void DNSServerBase::initialize(int stage) {
    if(stage == 0){
        cSimpleModule::initialize(stage);
        // Initialize gates
        //in.setOutputGate(gate("udpIn"));
        out.setOutputGate(gate("udpOut"));
        out.bind(DNS_PORT);

        queryCache = g_hash_table_new_full(g_int_hash, g_int_equal, free, NULL);

        receivedQueries = 0;
    }
    else if(stage == 3){
        rootServers = IPvXAddressResolver().resolve(cStringTokenizer(par("root_servers")).asVector());
    }
}

void DNSServerBase::handleMessage(cMessage *msg) {
    int isDNS = 0;
    int isQR = 0;
    ODnsExtension::Query* query;
    DNSPacket* response;

    // Check if we received a query
    if (msg->arrivedOn("udpIn")) {
        if ((isDNS = ODnsExtension::isDNSpacket((cPacket*) msg))) {
            if ((isQR = ODnsExtension::isQueryOrResponse((cPacket*) msg))
                    == 0) {
                query = ODnsExtension::resolveQuery((cPacket*) msg);
                receivedQueries++;

                response = handleQuery(query);

                if(response == NULL){ // only happens if recursive resolving was initiated
                    return;
                }

                // TODO: Find out how to get the source address
                // and send the response to the source address

                cPacket *pk = check_and_cast<cPacket *>(msg);
                UDPDataIndication *ctrl = check_and_cast<UDPDataIndication *>(
                        pk->getControlInfo());
                IPvXAddress srcAddress = ctrl->getSrcAddr();
                sendResponse(response, srcAddress);

                delete msg;
            }
            else{
                // Just got a response, lets see if its an answer fitting one of
                // the queries we need to resolved.

                response = handleRecursion((DNSPacket*) msg);

                if(response != NULL){
                    // this was the final answer, i.e.
                    // get the original packet and the src addr

                    uint32_t *key = (uint32_t*) malloc(sizeof(uint32_t));
                    *key = response->getId();
                    DNSPacket* original_query = (DNSPacket*) g_hash_table_lookup(queryCache, key);
                    free(key);

                    cPacket *pk = check_and_cast<cPacket *>(original_query);
                    UDPDataIndication *ctrl = check_and_cast<UDPDataIndication *>(
                            pk->getControlInfo());
                    IPvXAddress srcAddress = ctrl->getSrcAddr();
                    sendResponse(response, srcAddress);
                }

            }
        }

    } else {
        delete msg;
    }

}

DNSPacket* DNSServerBase::handleRecursion(DNSPacket* packet){
    // first check if we have a query id that belongs to this packet
    // and the answer relates to the query

    DNSPacket* response;

    uint32_t *key = (uint32_t*) malloc(sizeof(uint32_t));
    *key = (uint32_t) packet->getId();

    if(!g_hash_table_contains(queryCache, key)){
        return NULL; // we do not have a query that belongs to this key
    }

    DNSPacket* original_query = (DNSPacket*) g_hash_table_lookup(queryCache, key);
    free(key);

    // first check, see if there are actually answers
    if(packet->getAncount() == 0 && (packet->getNscount() == 0)){
        // return the entry not found response
        char *msg_name = g_strdup_printf("dns_response#%d", original_query->getId());
        response = ODnsExtension::createResponse(msg_name, 1,
                                    0, 0, 0, original_query->getId(), DNS_HEADER_OPCODE(original_query->getOptions()), 1,
                                    DNS_HEADER_RD(original_query->getOptions()), 1, 3);

        return response; // return the response with no entry found..
    }
    else if(packet->getAncount() > 0){
        // we have an answer for a query

        // TODO: check if it's for a nameserver
        //
        DNSRecord *answer = &packet->getAnswers(0);

        if(g_strcmp0(answer->rname, answer->rname) == 0){
            // this is the answer we were looking for

            // sanity check: check if qtype matches answer type
            // except if it was an any request..

            if(!original_query->getQuestions(0).qtype == DNS_TYPE_VALUE_ANY && original_query->getQuestions(0).qtype != answer->rtype){
                // this is not what we were looking for
            }

            // take this response and send it to the DNSClient
            return packet; // since this packet is fine we pass it upwards

        }
    }
    else{
        // Authority section has entries. Use those nameservers to resolve
        // the query

        // first see if there are A records for the nameservers..
        if(packet->getArcount() > 0){
            // we can directly query the name server ...
            // pick one at random

            int p = intrand(packet->getNscount());
            DNSRecord *r = &packet->getAdditional(p);

            // query the name server for our original query
            char *msg_name = g_strdup_printf("dns_query#%d--recursive", original_query->getId());
            DNSPacket *query = ODnsExtension::createQuery(msg_name, original_query->getQuestions(0).qname, DNS_CLASS_IN, original_query->getQuestions(0).qtype, original_query->getId(), 1);

            // Resolve the ip address for the record
            IPvXAddress address = IPvXAddressResolver().resolve(r->rdata);
            out.sendTo(query, address, DNS_PORT);

        }
        else{
            // we have to retrieve an A record for the nameserver first
            // however, since the responding server set up the authority
            // section, but didn't send a record, we start at the beginning
            // i.e. at the root server

            // TODO: implement this, for now make the hierarchy simple, i.e.,
            // there are no substitutes for domains such as de.vu which is
            // resolved by a name server outside the own domain.
        }
    }

    return NULL;
}

DNSPacket* DNSServerBase::handleQuery(ODnsExtension::Query* query) {
    return NULL;
}

void DNSServerBase::sendResponse(DNSPacket *response,
        IPvXAddress returnAddress) {
    out.sendTo(response, returnAddress, DNS_PORT);
}

DNSPacket* DNSServerBase::unsupportedOperation(ODnsExtension::Query *q) {
// TODO: return unsupported packet.
    return NULL;
}
