/* Copyright (c) 2014 Andreas Rain

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
    out.setOutputGate(gate("udpOut"));

    const char *dns_servers_ = par("dns_servers");
    cStringTokenizer tokenizer(dns_servers_);
    const char *token;

    while (tokenizer.hasMoreTokens()) {
        token = tokenizer.nextToken();
        dns_servers.push_back(IPvXAddressResolver().resolve(token));
    }

    response_cache = g_hash_table_new(g_str_hash, g_str_equal);
}

void DNSClient::handleMessage(cMessage *msg) {
    int isDNS = 0;
    int isQR = 0;
    gpointer addr;
    gpointer old;
    IPvXAddress tmp;
    ODnsExtension::Response* response;
    gboolean isInTable;

    if ((isDNS = ODnsExtension::isDNSpacket((cPacket*) msg)) && (isQR =
            ODnsExtension::isQueryOrResponse((cPacket*) msg))) {
        // Handle response, see if it belongs to a query that we've send previously...

        response = ODnsExtension::resolveResponse((cPacket*) msg);

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
                tmp = IPvXAddressResolver().resolve(
                        response->answers->rdata);
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
                                &(response->additional->rname[i]),
                                &old);
                    }
                }
            }

        }
    }
    // also check if internal message for resolving a dns name

    // Either:
    //  * Received DNS but it is a query. Just drop it, this is a client..
    //  * Not DNS, this packet is not meant for us, do nothing

}

IPvXAddress*
DNSClient::resolve(char* dns_name) {
    return NULL;
}

