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

#include "DNSClient.h"

Define_Module(DNSClient);

void DNSClient::initialize(int stage) {
    cSimpleModule::initialize(stage);
    // Initialize gates
    if(stage == inet::INITSTAGE_LOCAL){
        out.setOutputGate(gate("udpOut"));
        out.bind(DNS_PORT);
        query_count = 0;

        // the cache for the records
        cache = new INETDNS::DNSSimpleCache();

    }
    else if(stage == inet::INITSTAGE_LAST){
        const char *dns_servers_ = par("dns_servers");
        cStringTokenizer tokenizer(dns_servers_);
        const char *token;

        while (tokenizer.hasMoreTokens()) {
            token = tokenizer.nextToken();
            dns_servers.push_back(inet::L3AddressResolver().resolve(token));
        }
    }
}

void DNSClient::handleMessage(cMessage *msg) {
    int isDNS = 0;
    int isQR = 0;
    void (*callback) (int, void*);
    void *callback_handle;
    inet::L3Address tmp;
    std::shared_ptr<INETDNS::Response> response;

    if ((isDNS = INETDNS::isDNSpacket((cPacket*) msg)) && (isQR =
            INETDNS::isQueryOrResponse((cPacket*) msg))) {
        // Handle response, see if it belongs to a query that we've send previously...

        response = INETDNS::resolveResponse((cPacket*) msg);
        // So if the RCODE is not 0, according to RFC1035
        // something went wrong
        int rcode = DNS_HEADER_RCODE(response->options);
        switch(rcode){
            case 0: break; // everythings fine
            case 1: break; // Format error
            case 2:  // Server failure
                // make a query to the secondary DNS using the same
                // ID, the same callback and same dns query name
                // TODO: redo this part .. this is not going to work
//                fallback_dnsname = (char*) g_hash_table_lookup(queries, &response->id);
//                callback = (void (*) (int, void*)) g_hash_table_lookup(callbacks, &response->id);
//                callback_handle = (void *) g_hash_table_lookup(callback_handles, &response->id);
//                g_hash_table_remove(queries, &response->id);
//                resolve(fallback_dnsname, 0, callback, response->id, callback_handle);
                return;

            case 3: break; // Name error
            case 5: break; // Policy reasons forbid the server to perform the operations
            default: break; // Malformed packet somehow
        }

        // put records in the cache
        // this is simply choice, the cache chooses what stays and what doesn't.
#ifdef DEBUG_ENABLED
        std::string bubble_popup = "Resolved query: ";
        std::cout << "**********************\nResolved query:\n\n;;Question Section:\n";
        DNSPacket* q = queries[response->id];
        std::shared_ptr<DNSQuestion> question = INETDNS::copyDnsQuestion(&q->getQuestions(0));
        INETDNS::printDNSQuestion(question);
        bubble_popup.append(q->getQuestions(0).qname);
        bubble_popup.append("\n");
        delete q;

        bubble_popup.append(";;Answer Section:\n");
        std::cout << "\n;;Answer Section:\n";
#endif
        for(int i = 0; i < response->ancount; i++){
            std::shared_ptr<DNSRecord> r = INETDNS::copyDnsRecord(&response->answers[i]);
#ifdef DEBUG_ENABLED
            INETDNS::printDNSRecord(r);
            bubble_popup.append(r->rname);
            bubble_popup.append(":");
            bubble_popup.append(INETDNS::getTypeStringForValue(r->rtype));
            bubble_popup.append(":");
            bubble_popup.append(INETDNS::getClassStringForValue(r->rclass));
            bubble_popup.append("\nData: ");
            bubble_popup.append(r->strdata);
            bubble_popup.append("\n");
#endif
            cache->put_into_cache(r);
        }

#ifdef DEBUG_ENABLED
        bubble_popup.append(";;Authority Section:\n");
        std::cout << "\n;;Authority Section:\n";
#endif
        for(int i = 0; i < response->nscount; i++){
            std::shared_ptr<DNSRecord> r = INETDNS::copyDnsRecord(&response->authoritative[i]);
#ifdef DEBUG_ENABLED
            bubble_popup.append(r->rname);
            bubble_popup.append(":");
            bubble_popup.append(INETDNS::getTypeStringForValue(r->rtype));
            bubble_popup.append(":");
            bubble_popup.append(INETDNS::getClassStringForValue(r->rclass));
            bubble_popup.append("\nData: ");
            bubble_popup.append(r->strdata);
            bubble_popup.append("\n");
#endif
            cache->put_into_cache(r);
        }

#ifdef DEBUG_ENABLED
        bubble_popup.append(";;Additional Section:\n");
        std::cout << "\n;;Additional Section:\n";
#endif
        for(int i = 0; i < response->arcount; i++){
            std::shared_ptr<DNSRecord> r = INETDNS::copyDnsRecord(&(response->additional[i]));
#ifdef DEBUG_ENABLED
            INETDNS::printDNSRecord(r);
            bubble_popup.append(r->rname);
            bubble_popup.append(":");
            bubble_popup.append(INETDNS::getTypeStringForValue(r->rtype));
            bubble_popup.append(":");
            bubble_popup.append(INETDNS::getClassStringForValue(r->rclass));
            bubble_popup.append("\nData: ");
            bubble_popup.append(r->strdata);
            bubble_popup.append("\n");
#endif
            cache->put_into_cache(r);
        }

#ifdef DEBUG_ENABLED
        EV << bubble_popup.c_str();
        this->getParentModule()->bubble(bubble_popup.c_str());
        std::cout << "**********************\n";
#endif

        queries.erase(response->id);

        // call the callback and tell it that the query finished
        // the response is now in the cache and can be used..
        callback = callbacks[response->id];
        callback_handle = callback_handles[response->id];
        callback(response->id, callback_handle);

    }
    // also check if internal message for resolving a dns name

    // Either:
    //  * Received DNS but it is a query. Just drop it, this is a client..
    //  * Not DNS, this packet is not meant for us, do nothing

}

inet::L3Address * DNSClient::getAddressFromCache(std::string dns_name){

    // TODO: Rethink cache, IPvXAddress cache is not very useful..
//    gboolean inTable = g_hash_table_contains(response_cache, dns_name);
//    if(inTable){
//        gpointer p = g_hash_table_lookup(response_cache, dns_name);
//        IPvXAddress* address = (IPvXAddress*) p;
//        return address;
//    }

    return NULL;

}

int DNSClient::resolve(std::string dns_name, int qtype, int primary, void (*callback) (int, void*), int id, void * handle) {
    //First check if we already resolved this.
    DNSPacket* query;

    // create query
    std::string msg_name;

    if(id == -1){
        msg_name = std::string("dns_query#") + std::to_string(query_count);
    }
    else{
        msg_name = std::string("dns_query#") + std::to_string(id);
    }
    query = INETDNS::createQuery(msg_name, dns_name, DNS_CLASS_IN, qtype, query_count, 1);


    // put it into the hash table for the given query_count number, so we can identify the query
    // Put a copy into the cache, if we need to check it later again
    // this way the server can without a problem delete the msg.
    DNSPacket* query_dup = query->dup();
    queries[query_count] = query_dup;
    callbacks[query_count] = callback;
    callback_handles[query_count] = handle;

    // Send this packet to the primary DNS server, if that fails, the secondary DNS server

    query->setByteLength(INETDNS::estimateDnsPacketSize(query));
    if(primary){
        out.sendTo(query, dns_servers[0], DNS_PORT);
    }
    else{
        out.sendTo(query, dns_servers[1], DNS_PORT);
    }

    return query_count++;
}

