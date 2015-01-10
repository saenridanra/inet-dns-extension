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

#ifndef DNSTOOLS_H_
#define DNSTOOLS_H_

/*
 * Include omnetpp header
 */
#include <omnetpp.h>

/*
 * DNSPacket_m.h
 */

#include "../common/DNS.h"
#include "../messages/DNSPacket_m.h"
#include "glib.h"
#include "glib/gprintf.h"


/**
 * @brief DNSTools provides methods for creating
 * DNS queries and responses, as well resolving (parsing)
 * queries and responses.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 */
namespace ODnsExtension {

/**
 * Define some errors here:
 */

// The packet was not a DNS Packet
#define E_NOT_A_DNSPACKET 1;
#define E_BAD_INDEX 2;
#define E_WRONG_QR 3;

/**
 * @brief createQuery
 *      Creates simple DNS Queries for exactly one question
 *      (usually used by dns clients).
 */
DNSPacket* createQuery(char *msg_name, char *name, unsigned short dnsclass, unsigned short type,
        unsigned short id, unsigned short rd);

/**
 * @brief createNQuery
 *      Creates a query with multiple questions
 */

DNSPacket* createNQuery(char *msg_name, unsigned short qdcount, char **name, unsigned short dnsclass,
        unsigned short type, unsigned short id, unsigned short rd);

/**
 * @brief resolveQuery
 *      Extracts information in order to resolve a DNS query.
 */
struct Query* resolveQuery(cPacket* query);

/**
 * @brief createResponse
 *      Creates a dns response header.
 */
DNSPacket* createResponse(char *msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount,
        unsigned short arcount, unsigned short id, unsigned short opcode, unsigned short AA, unsigned short rd,
        unsigned short ra, unsigned short rcode);

/**
 * @brief appendAnswer
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAnswer(DNSPacket *p, ODnsExtension::DNSRecord *r, int index);

/**
 * @brief appendAuthority
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAuthority(DNSPacket *p, ODnsExtension::DNSRecord *r, int index);

/**
 * @brief appendAdditional
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAdditional(DNSPacket *p, ODnsExtension::DNSRecord *r, int index);

/**
 * @brief resolveResponse
 *      Extracts information in order to resolve a DNS response.
 */
struct Response* resolveResponse(cPacket *response);

/**
 * @brief isDNSPacket
 *      Determine whether p is a DNS packet
 *
 * @return
 *      0 false, 1 true
 */
int isDNSpacket(cPacket *p);

/**
 * @brief isQueryOrResponse
 *      Determine whether p is a query or response.
 *
 * @return
 *      0 if Query, 1 if Response
 */
int isQueryOrResponse(cPacket *p);

/**
 * @brief getTypeArray
 *      returns a type array with all DNS type strings
 */
const char** getTypeArray();

/**
 * @brief getTypeStringForValue
 *      Get the given DNS_TYPE_STR value for a DNS_TYPE_VALUE
 *
 * @return
 *      the desired string value.
 */
const char* getTypeStringForValue(int type);

/**
 * @brief getTypeStringForValue
 *      Get the given DNS_TYPE_VALUE value for a DNS_TYPE_STR
 *
 * @return
 *      the according type value.
 */
int getTypeValueForString(char* type);

/**
 * @brief getClassStringForValue
 *      Get the given DNS_CLASS_STR value for a DNS_CLASS
 *
 * @return
 *      the desired string value.
 */
const char* getClassStringForValue(int _class);

/**
 * @brief printDNSRecord
 *      prints a dns record to stdout using g_printf
 */
void printDNSRecord(DNSRecord* r);

/**
 * @brief printDNSQuestion
 *      prints a dns question to stdout using g_printf
 */
void printDNSQuestion(DNSQuestion* q);

/**
 * @brief freeDnsRecord
 *      frees the given dns record
 * @return
 *      1 if successful
 *      0 otherwise
 */
int freeDnsRecord(DNSRecord* r);


}

#endif /* DNSTOOLS_H_ */
