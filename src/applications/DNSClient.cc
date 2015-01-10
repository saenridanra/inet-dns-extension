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
    if(stage == 0){
        out.setOutputGate(gate("udpOut"));
        out.bind(DNS_PORT);
        query_count = 0;

        queries = g_hash_table_new(g_int_hash, g_int_equal);
        callbacks = g_hash_table_new(g_int_hash, g_int_equal);
        callback_handles = g_hash_table_new(g_int_hash, g_int_equal);

        // the cache for the records
        cache = new ODnsExtension::DNSSimpleCache();

    }
    else if(stage == 3){
        const char *dns_servers_ = par("dns_servers");
        cStringTokenizer tokenizer(dns_servers_);
        const char *token;

        while (tokenizer.hasMoreTokens()) {
            token = tokenizer.nextToken();
            dns_servers.push_back(IPvXAddressResolver().resolve(token));
        }
    }
}

void DNSClient::handleMessage(cMessage *msg) {
    int isDNS = 0;
    int isQR = 0;
    char* fallback_dnsname;
    void (*callback) (int, void*);
    void *callback_handle;
    IPvXAddress tmp;
    ODnsExtension::Response* response;

    if ((isDNS = ODnsExtension::isDNSpacket((cPacket*) msg)) && (isQR =
            ODnsExtension::isQueryOrResponse((cPacket*) msg))) {
        // Handle response, see if it belongs to a query that we've send previously...

        response = ODnsExtension::resolveResponse((cPacket*) msg);
        // So if the RCODE is not 0, according to RFC1035
        // something went wrong
        int rcode = DNS_HEADER_RCODE(response->options);
        switch(rcode){
            case 0: break; // everythings fine
            case 1: break; // Format error
            case 2:  // Server failure
                // make a query to the secondary DNS using the same
                // ID, the same callback and same dns query name
                fallback_dnsname = (char*) g_hash_table_lookup(queries, &response->id);
                callback = (void (*) (int, void*)) g_hash_table_lookup(callbacks, &response->id);
                callback_handle = (void *) g_hash_table_lookup(callback_handles, &response->id);
                g_hash_table_remove(queries, &response->id);
                resolve(fallback_dnsname, 0, callback, response->id, callback_handle);
                return;

            case 3: break; // Name error
            case 5: break; // Policy reasons forbid the server to perform the operations
            default: break; // Malformed packet somehow
        }

        // put records in the cache
        // this is simply choice, the cache chooses what stays and what doesn't.
        //g_printf("DEBUG MSG: Checking CACHE --- [ancount=%u,nscount=%u,arcount=%u]\n", response->ancount, response->nscount, response->arcount);

        for(int i = 0; i < response->ancount; i++){
            DNSRecord* r = &response->answers[i];
            cache->put_into_cache(r);
        }

        for(int i = 0; i < response->nscount; i++){
            DNSRecord* r = &response->authoritative[i];
            cache->put_into_cache(r);
        }

        for(int i = 0; i < response->arcount; i++){
            DNSRecord* r = &response->additional[i];
            cache->put_into_cache(r);
        }

        g_hash_table_remove(queries, &response->id);

        // call the callback and tell it that the query finished
        // the response is now in the cache and can be used..
        uint32_t* key;
        key=(uint32_t *)malloc(sizeof(uint32_t));
        *key = response->id;
        callback = (void (*) (int, void*)) g_hash_table_lookup(callbacks, key);
        callback_handle = (void *) g_hash_table_lookup(callback_handles, key);
        callback(*key, callback_handle);
        free(key);

    }
    // also check if internal message for resolving a dns name

    // Either:
    //  * Received DNS but it is a query. Just drop it, this is a client..
    //  * Not DNS, this packet is not meant for us, do nothing

}

IPvXAddress * DNSClient::getAddressFromCache(char* dns_name){

    // TODO: Rethink cache, IPvXAddress cache is not very useful..
//    gboolean inTable = g_hash_table_contains(response_cache, dns_name);
//    if(inTable){
//        gpointer p = g_hash_table_lookup(response_cache, dns_name);
//        IPvXAddress* address = (IPvXAddress*) p;
//        return address;
//    }

    return NULL;

}

int DNSClient::resolve(char* dns_name, int primary, void (*callback) (int, void*), int id, void * handle) {
    //First check if we already resolved this.
    DNSPacket* query;

    // create query
    char msg_name[20];

    if(id == -1){
        sprintf(msg_name, "dns_query#%d", query_count);
    }
    else{
        sprintf(msg_name, "dns_query#%d", id);
    }
    query = ODnsExtension::createQuery(msg_name, dns_name, DNS_CLASS_IN, DNS_TYPE_VALUE_A, query_count, 1);


    // put it into the hash table for the given query_count number, so we can identify the query
    uint32_t* key;
    key=(uint32_t *)malloc(sizeof(uint32_t));
    *key = query_count;
    g_hash_table_insert(queries, key, &dns_name);
    key=(uint32_t *)malloc(sizeof(uint32_t));
    *key = query_count;
    g_hash_table_insert(callbacks, key, (gpointer) callback);
    key=(uint32_t *)malloc(sizeof(uint32_t));
    *key = query_count;
    g_hash_table_insert(callback_handles, key, (gpointer) handle);

    // Send this packet to the primary DNS server, if that fails, the secondary DNS server

    if(primary){
        out.sendTo(query, dns_servers[0], DNS_PORT);
    }
    else{
        out.sendTo(query, dns_servers[1], DNS_PORT);
    }

    return query_count++;
}

