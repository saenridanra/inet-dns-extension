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

void DNSClient::initialize() {
    // Initialize gates
    out.setOutputGate(gate("udpOut"));
    in.setOutputGate(gate("udpIn"));
    in.bind(DNS_PORT);
    query_count = 0;

    const char *dns_servers_ = par("dns_servers");
    cStringTokenizer tokenizer(dns_servers_);
    const char *token;

    while (tokenizer.hasMoreTokens()) {
        token = tokenizer.nextToken();
        dns_servers.push_back(IPvXAddressResolver().resolve(token));
    }

    queries = g_hash_table_new(g_int_hash, g_int_equal);
    callbacks = g_hash_table_new(g_int_hash, g_int_equal);
    callback_handles = g_hash_table_new(g_int_hash, g_int_equal);
    response_cache = g_hash_table_new(g_str_hash, g_str_equal);
}

void DNSClient::handleMessage(cMessage *msg) {
    int isDNS = 0;
    int isQR = 0;
    char* fallback_dnsname;
    void (*callback) (int, void*);
    void *callback_handle;
    gpointer addr;
    gpointer old;
    IPvXAddress tmp;
    ODnsExtension::Response* response;
    gboolean isInTable;

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
                break;

            case 3: break; // Name error
            case 5: break; // Policy reasons forbid the server to perform the operations
            default: break; // Malformed packet somehow
        }


        // Use our hashmap, and put the DNSServer in the response inside.
        for (int i = 0; i < response->nscount; i++) {
            // handle authoritative responses
            isInTable = g_hash_table_contains(response_cache,
                    &(response->authoritative->rname[i]));
            if (isInTable) {
                // Update entry
                old = g_hash_table_lookup(response_cache,
                        &(response->authoritative->rname[i]));
                g_hash_table_remove(response_cache,
                        &(response->authoritative->rname[i]));
            }

            // The IPvXAddressResolveer will detect a malformed address, so we will not take those
            try {
                gpointer p = malloc(sizeof(IPvXAddress));
                tmp = IPvXAddressResolver().resolve(
                        response->authoritative->rdata);
                memcpy(p, &tmp, sizeof(IPvXAddress));
                addr = p;
                free(p);

                g_hash_table_insert(response_cache,
                        &(response->authoritative->rname[i]), addr);
            } catch (int e) {
                // exception, not valid, reinsert old entry
                if (isInTable) {
                    g_hash_table_insert(response_cache,
                            &(response->authoritative->rname[i]), old);
                }
            }
        }

        // Use our hashmap, and put the DNSServer in the response inside.
        for (int i = 0; i < response->nscount; i++) {
            // handle authoritative responses
            isInTable = g_hash_table_contains(response_cache,
                    &(response->answers->rname[i]));
            if (isInTable) {
                // Update entry
                old = g_hash_table_lookup(response_cache,
                        &(response->answers->rname[i]));
                g_hash_table_remove(response_cache,
                        &(response->answers->rname[i]));
            }

            // The IPvXAddressResolveer will detect a malformed address, so we will not take those
            try {

                gpointer p = malloc(sizeof(IPvXAddress));
                tmp = IPvXAddressResolver().resolve(response->answers->rdata);
                memcpy(p, &tmp, sizeof(IPvXAddress));
                addr = p;
                free(p);

                g_hash_table_insert(response_cache,
                        &(response->answers->rname[i]), addr);
            } catch (int e) {
                // exception, not valid, reinsert old entry
                if (isInTable) {
                    g_hash_table_insert(response_cache,
                            &(response->answers->rname[i]), old);
                }
            }
        }

        for (int i = 0; i < response->arcount; i++) {
            // Handle response, see if it belongs to a query that we've send previously...

            response = ODnsExtension::resolveResponse((cPacket*) msg);

            // Use our hashmap, and put the DNSServer in the response inside.
            for (int i = 0; i < response->nscount; i++) {
                // handle authoritative responses
                isInTable = g_hash_table_contains(response_cache,
                        &(response->additional->rname[i]));
                if (isInTable) {
                    // Update entry
                    old = g_hash_table_lookup(response_cache,
                            &(response->additional->rname[i]));
                    g_hash_table_remove(response_cache,
                            &(response->additional->rname[i]));
                }

                // The IPvXAddressResolveer will detect a malformed address, so we will not take those
                try {
                    gpointer p = malloc(sizeof(IPvXAddress));
                    tmp = IPvXAddressResolver().resolve(
                            response->additional->rdata);
                    memcpy(p, &tmp, sizeof(IPvXAddress));
                    addr = p;
                    free(p);

                    g_hash_table_insert(response_cache,
                            &(response->additional->rname[i]), &addr);
                } catch (int e) {
                    // exception, not valid, reinsert old entry
                    if (isInTable) {
                        g_hash_table_insert(response_cache,
                                &(response->additional->rname[i]), &old);
                    }
                }
            }

        }

        // Everythings fine if we get here, so use ID to identify the query in the
        // hash table and remove it, since we have our response

        g_hash_table_remove(queries, &response->id);

        // call the callback and tell it that the query finished
        // the response is now in the cache and can be used..
        callback = (void (*) (int, void*)) g_hash_table_lookup(callbacks, &response->id);
        callback_handle = (void *) g_hash_table_lookup(callback_handles, &response->id);
        callback(response->id, callback_handle);

    }
    // also check if internal message for resolving a dns name

    // Either:
    //  * Received DNS but it is a query. Just drop it, this is a client..
    //  * Not DNS, this packet is not meant for us, do nothing

}

IPvXAddress * DNSClient::getAddressFromCache(char* dns_name){

    gboolean inTable = g_hash_table_contains(response_cache, dns_name);
    if(inTable){
        gpointer p = g_hash_table_lookup(response_cache, dns_name);
        IPvXAddress* address = (IPvXAddress*) p;
        return address;
    }

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
    g_hash_table_insert(queries, &query_count, &dns_name);
    g_hash_table_insert(callbacks, &query_count, &callback);
    g_hash_table_insert(callback_handles, &query_count, &handle);

    // Send this packet to the primary DNS server, if that fails, the secondary DNS server

    if(primary){
        out.sendTo(query, dns_servers[0], DNS_PORT);
    }
    else{
        out.sendTo(query, dns_servers[1], DNS_PORT);
    }

    return query_count;
}

