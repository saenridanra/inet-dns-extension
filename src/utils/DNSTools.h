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
#include "../messages/DNSPacket_m.h"

#include "../common/DNS.h"

#include <memory>
#include "string.h"


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
DNSPacket* createQuery(std::string msg_name, std::string name, unsigned short dnsclass, unsigned short type,
        unsigned short id, unsigned short rd);

/**
 * @brief createNQuery
 *      Creates a query with multiple questions
 */

DNSPacket* createNQuery(std::string msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount, unsigned short arcount, unsigned short id, unsigned short rd);

/**
 * @brief resolveQuery
 *      Extracts information in order to resolve a DNS query.
 */
struct std::shared_ptr<Query> resolveQuery(cPacket* query);

/**
 * @brief createResponse
 *      Creates a dns response header.
 */
DNSPacket* createResponse(std::string msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount,
        unsigned short arcount, unsigned short id, unsigned short opcode, unsigned short AA, unsigned short rd,
        unsigned short ra, unsigned short rcode);


/**
 * @brief appendQuestion
 *      Appends a question to a previously generated DNS packet.
 */
int appendQuestion(DNSPacket*p, std::shared_ptr<DNSQuestion> q, int index);

/**
 * @brief appendAnswer
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAnswer(DNSPacket* p, std::shared_ptr<DNSRecord> r, int index);

/**
 * @brief appendAuthority
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAuthority(DNSPacket* p, std::shared_ptr<DNSRecord> r, int index);

/**
 * @brief appendAdditional
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAdditional(DNSPacket* p, std::shared_ptr<DNSRecord> r, int index);

/**
 * @brief resolveResponse
 *      Extracts information in order to resolve a DNS response.
 */
struct std::shared_ptr<Response> resolveResponse(cPacket* response);

/**
 * @brief isDNSPacket
 *      Determine whether p is a DNS packet
 *
 * @return
 *      0 false, 1 true
 */
int isDNSpacket(cPacket* p);

/**
 * @brief isQueryOrResponse
 *      Determine whether p is a query or response.
 *
 * @return
 *      0 if Query, 1 if Response
 */
int isQueryOrResponse(cPacket* p);

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
std::string getTypeStringForValue(int type);

/**
 * @brief getTypeStringForValue
 *      Get the given DNS_TYPE_VALUE value for a DNS_TYPE_STR
 *
 * @return
 *      the according type value.
 */
int getTypeValueForString(std::string type);

/**
 * @brief getClassStringForValue
 *      Get the given DNS_CLASS_STR value for a DNS_CLASS
 *
 * @return
 *      the desired string value.
 */
std::string getClassStringForValue(int _class);

/**
 * @brief dnsPacketToString
 *
 * @return
 *      returns a char sequence representing the dnspacket
 */

std::string dnsPacketToString(DNSPacket* packet);

/**
 * @brief estimateDnsPacketSize
 *
 * @return
 *      The size of the DNSPacket
 */

int estimateDnsPacketSize(DNSPacket* packet);

/**
 * @brief printDNSRecord
 *      prints a dns record to stdout using g_printf
 */
void printDNSRecord(std::shared_ptr<DNSRecord> r);

/**
 * @brief printDNSQuestion
 *      prints a dns question to stdout using g_printf
 */
void printDNSQuestion(std::shared_ptr<DNSQuestion> q);

/**
 * @brief freeDnsQuestion
 *      frees the given dns question
 * @return
 *      1 if successful
 *      0 otherwise
 */
int freeDnsQuestion(std::shared_ptr<DNSQuestion> q);

/**
 * @brief freeDnsRecord
 *      frees the given dns record
 * @return
 *      1 if successful
 *      0 otherwise
 */
int freeDnsRecord(std::shared_ptr<DNSRecord> r);

/**
 * @brief copyDnsRecord
 *  creates a hard-copy of a given dns record.
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSRecord> copyDnsRecord(std::shared_ptr<DNSRecord> r);

/**
 * @brief copyDnsRecord
 *  creates a hard-copy of a given dns record.
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSRecord> copyDnsRecord(DNSRecord* r);

/**
 * @brief copyDnsQuestion
 *  creates a hard-copy of a given dns question.
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSQuestion> copyDnsQuestion(std::shared_ptr<DNSQuestion> q);

/**
 * @brief copyDnsQuestion
 *  creates a hard-copy of a given dns question, given a shared pointer to the object.
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSQuestion> copyDnsQuestion(DNSQuestion* q);

/**
 * @brief recordDataEqual
 *  compared rdata or strdata depending on type
 *  and checks if data is equal
 *
 * @return
 *      true if the records are equal
 */
int recordDataEqual(std::shared_ptr<DNSRecord> r1, std::shared_ptr<DNSRecord> r2);

/**
 * @brief recordEqualNoData
 * compares records without comparing their data
 *
 * @return
 *      true if the records are equal (without data)
 */
int recordEqualNoData(std::shared_ptr<DNSRecord> r1, std::shared_ptr<DNSRecord> r2);

}

#endif /* DNSTOOLS_H_ */
