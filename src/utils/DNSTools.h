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

/**
 * @file DNSTools.h
 *
 * Contains utility functions to handle records, questions, queries
 * and responses.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */

#ifndef DNSTOOLS_H_
#define DNSTOOLS_H_

#include <omnetpp.h>
#include "../messages/DNSPacket_m.h"

#include "../common/DNS.h"

#include <memory>
#include "string.h"

namespace ODnsExtension {

// The packet was not a DNS Packet
#define E_NOT_A_DNSPACKET 1;
#define E_BAD_INDEX 2;
#define E_WRONG_QR 3;

/**
 * @brief Creates simple DNS Queries for exactly one question (usually used by dns clients).
 *
 * @param msg_name The name the @ref DNSPacket should have.
 * @param name The query string.
 * @param dnsclass The dns class value.
 * @param type The dns type value.
 * @param id The id for this query.
 * @param rd Whether recursion is desired.
 *
 * @return A newly created @ref DNSPacket based on the parameters.
 */
DNSPacket* createQuery(std::string msg_name, std::string name, unsigned short dnsclass, unsigned short type,
        unsigned short id, unsigned short rd);

/**
 * @brief Creates a query with multiple questions.
 *
 * @param msg_name The name the @ref DNSPacket should have.
 * @param qdcount The amount of questions in the query.
 * @param ancount The amount of answers in the query.
 * @param nscount The amount of authoritative records in the query.
 * @param arcount The amount of additional records in the query.
 * @param id The id for this query.
 * @param rd Whether recursion is desired.
 *
 * @return A newly created @ref DNSPacket based on the parameters.
 */
DNSPacket* createNQuery(std::string msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount, unsigned short arcount, unsigned short id, unsigned short rd);

/**
 * @brief Extracts information in order to resolve a DNS query.
 *
 * @param query @ref cPacket that needs to be resolved.
 *
 * @return Smart pointer to a newly created @ref Query.
 *
 */
struct std::shared_ptr<Query> resolveQuery(cPacket* query);

/**
 * @brief Creates a dns response header.
 *
 * @param msg_name The name the @ref DNSPacket should have.
 * @param qdcount The amount of questions in the response.
 * @param ancount The amount of answers in the response.
 * @param nscount The amount of authoritative records in the response.
 * @param arcount The amount of additional records in the response.
 * @param id The id for this query.
 * @param opcode The opcode of this response, according to RFC 1035.
 * @param AA whether this response is authoritative.
 * @param rd Whether recursion is desired.
 * @param ra Whether recursion was available.
 * @param rcode The response code, according to RFC 1035.
 *
 * @return A newly created @ref DNSPacket based on the parameters.
 */
DNSPacket* createResponse(std::string msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount,
        unsigned short arcount, unsigned short id, unsigned short opcode, unsigned short AA, unsigned short rd,
        unsigned short ra, unsigned short rcode);


/**
 * @brief Appends a question to a previously generated DNS packet.
 *
 * @param p @ref DNSPacket to which a question should be appended.
 * @param q @ref DNSQuestion which has to be appended.
 * @param index the position in the array at which the question has to be inserted.
 *
 * @return 1 if successful, 0 otherwise
 */
int appendQuestion(DNSPacket*p, std::shared_ptr<DNSQuestion> q, int index);

/**
 * @brief Appends an answer to a previously generated DNS packet.
 *
 * @param p @ref DNSPacket to which a record should be appended.
 * @param r @ref DNSRecord which has to be appended.
 * @param index the position in the array at which the record has to be inserted.
 *
 * @return 1 if successful, 0 otherwise
 */
int appendAnswer(DNSPacket* p, std::shared_ptr<DNSRecord> r, int index);

/**
 * @brief Appends an answer to a previously generated DNS packet.
 *
 * @param p @ref DNSPacket to which a record should be appended.
 * @param r @ref DNSRecord which has to be appended.
 * @param index the position in the array at which the record has to be inserted.
 *
 * @return 1 if successful, 0 otherwise
 */
int appendAuthority(DNSPacket* p, std::shared_ptr<DNSRecord> r, int index);

/**
 * @brief Appends an answer to a previously generated DNS packet.
 *
 * @param p @ref DNSPacket to which a record should be appended.
 * @param r @ref DNSRecord which has to be appended.
 * @param index the position in the array at which the record has to be inserted.
 *
 * @return 1 if successful, 0 otherwise
 */
int appendAdditional(DNSPacket* p, std::shared_ptr<DNSRecord> r, int index);

/**
 * @brief Extracts information in order to resolve a DNS response.
 *
 * @param response The response packet that needs to be resolved.
 *
 * @return Smart pointer to a newly created @ref Response .
 */
struct std::shared_ptr<Response> resolveResponse(cPacket* response);

/**
 * @brief Determine whether p is a DNS packet.
 *
 * @param p The packet that needs to be checked.
 *
 * @return
 *      1 if true, 0 otherwise
 */
int isDNSpacket(cPacket* p);

/**
 * @brief Determine whether p is a query or response.
 *
 * @param p The packet that needs to be checked.
 *
 * @return
 *      0 if Query, 1 if Response
 */
int isQueryOrResponse(cPacket* p);

/**
 * @return returns a type array with all DNS type strings
 */
const char** getTypeArray();

/**
 * @brief Get the given DNS_TYPE_STR value for a DNS_TYPE_VALUE
 *
 * @param type integer value of the dns type
 *
 * @return
 *      the desired string value.
 */
std::string getTypeStringForValue(int type);

/**
 * @brief Get the given DNS_TYPE_VALUE value for a DNS_TYPE_STR
 *
 * @param type string value of the dns type
 *
 * @return
 *      the according type value.
 */
int getTypeValueForString(std::string type);

/**
 * @brief Get the given DNS_CLASS_STR value for a DNS_CLASS
 *
 * @param _class integer value of the dns class
 *
 * @return
 *      the desired string value.
 */
std::string getClassStringForValue(int _class);

/**
 * @brief Pretty-prints a dns packet into a string
 *
 * @param p The packet that needs to be pretty-printed.
 *
 * @return
 *      returns a char sequence representing the dnspacket
 */
std::string dnsPacketToString(DNSPacket* packet);

/**
 * @brief Estimates the size of a dns packet
 *
 * @param p The packet that needs to be estimated.
 *
 * @return
 *      The size of the DNSPacket
 */
int estimateDnsPacketSize(DNSPacket* packet);

/**
 * @brief Prints a @ref DNSRecord to the standard output.
 *
 * @param r record that needs to be printed
 */
void printDNSRecord(std::shared_ptr<DNSRecord> r);

/**
 * @brief prints a @ref DNSQuestion to the standard output.
 *
 * @param q question that needs to be printed
 */
void printDNSQuestion(std::shared_ptr<DNSQuestion> q);

/**
 * @brief frees the given dns question
 * @param q question that needs to be freed
 * @return
 *      1 if successful
 *      0 otherwise
 */
int freeDnsQuestion(std::shared_ptr<DNSQuestion> q);

/**
 * @brief frees the given dns record
 * @param r record that needs to be freed
 * @return
 *      1 if successful
 *      0 otherwise
 */
int freeDnsRecord(std::shared_ptr<DNSRecord> r);

/**
 * @brief creates a hard-copy of a given dns record.
 *
 * @param r the record that needs to be copied
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSRecord> copyDnsRecord(std::shared_ptr<DNSRecord> r);

/**
 * @brief creates a hard-copy of a given dns record.
 *
 * @param r the record that needs to be copied
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSRecord> copyDnsRecord(DNSRecord* r);

/**
 * @brief creates a hard-copy of a given dns question.
 *
 * @param q the question that needs to be copied
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSQuestion> copyDnsQuestion(std::shared_ptr<DNSQuestion> q);

/**
 * @brief creates a hard-copy of a given dns question, given a shared pointer to the object.
 *
 * @param q the question that needs to be copied
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSQuestion> copyDnsQuestion(DNSQuestion* q);

/**
 * @brief compares rdata or strdata depending on the dns type and checks if data is equal
 *
 * @param r1 first record
 * @param r2 second record
 *
 * @return
 *      true if the records are equal
 */
int recordDataEqual(std::shared_ptr<DNSRecord> r1, std::shared_ptr<DNSRecord> r2);

/**
 * @brief compares records without comparing their data
 *
 * @param r1 first record
 * @param r2 second record
 *
 * @return
 *      true if the records are equal (without data)
 */
int recordEqualNoData(std::shared_ptr<DNSRecord> r1, std::shared_ptr<DNSRecord> r2);

}

#endif /* DNSTOOLS_H_ */
