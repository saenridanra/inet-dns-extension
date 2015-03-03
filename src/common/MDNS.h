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


#ifndef OPP_DNS_EXTENSION_MDNS_H_
#define OPP_DNS_EXTENSION_MDNS_H_

#include <omnetpp.h>
#include <DNS.h>
#include <DNSTools.h>
#include "DNSPacket_m.h"

namespace ODnsExtension {

// definition of a structure for services
// this is a basic definition without
// subtypes
typedef struct MDNSService{
   char* service_type;
   char* name;
   GList* txtrecords;
   int   port;
} mdns_service;

typedef struct MDNSKey{
   char* name;
   uint16_t type;
   uint16_t _class;
} mdns_key;

// utility functions:
int isProbe(DNSPacket* p);
int isAnnouncement(DNSPacket* p);
int isQuery(DNSPacket* p);
int isResponse(DNSPacket* p);
int isGoodbye(DNSRecord* r);

int compareMDNSKey(ODnsExtension::MDNSKey* key1, ODnsExtension::MDNSKey* key2);
int compareMDNSKeyANY(ODnsExtension::MDNSKey* key1, ODnsExtension::MDNSKey* key2);
MDNSKey* mdns_key_new(char* name, int type, int _class);
void mdns_key_free(MDNSKey* key);

/**
 * @brief createQuestion
 *
 * Creates a dnsquestion from params
 */
DNSQuestion* createQuestion(char* name, unsigned short type, unsigned short _class);

/**
 * @brief createQuestionFromKey
 *
 * Creates a dnsquestion from an MDNSKey
 */
DNSQuestion* createQuestionFromKey(MDNSKey* key);

#define MAX_MDNS_PACKET_SIZE 8000 // leaving plenty of room for UDP + IP + ETHERNET, since max size is 9000
#define MDNS_PORT 5353
#define MDNS_HOST_TTL 120
#define MDNS_SERVICE_TTL 60*75

}

#endif /* MDNS_H_ */
