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

#include <DNSTools.h>

namespace ODnsExtension {

DNSTools::DNSTools()
{
}

DNSTools::~DNSTools()
{
}

/**
 * @brief createQuery
 *      Creates simple DNS Queries for exactly one question
 *      (usually used by dns clients).
 */
DNSPacket* createQuery(char *msg_name, char *name, unsigned short dnsclass, unsigned short type, unsigned short id,
        unsigned short rd)
{
    DNSPacket *q = new DNSPacket(msg_name);

    // Set id and options in header ..
    q->setId(id);
    q->setQdcount(1);
    q->setAncount(0);
    q->setNscount(0);
    q->setArcount(0);

    unsigned short options = 0;
    // QR and OPCODE already 0..
    // Recursion desired ..
    DNS_HEADER_SET_RD(options, rd);

    // Setup question

    q->setNumQuestions(1);
    DNSQuestion question;
    question.qname = name;
    question.qclass = dnsclass;
    question.qtype = type;
    q->setQuestions(0, question); // in this case we vary from standard implementations
                                  // questions are appended as array in DNSPacket

    return q;
}

/**
 * @brief createNQuery
 *      Creates a query with multiple questions
 */

DNSPacket* createNQuery(char *msg_name, unsigned short qdcount, char **name, unsigned short dnsclass,
        unsigned short type, unsigned short id, unsigned short rd)
{
    DNSPacket *q = new DNSPacket(msg_name);

    // Set id and options in header ..
    q->setId(id);
    q->setQdcount(qdcount);
    q->setAncount(0);
    q->setNscount(0);
    q->setArcount(0);

    unsigned short options = 0;
    // QR and OPCODE already 0..
    // Recursion desired ..
    DNS_HEADER_SET_RD(options, rd);

    // Setup question
    q->setNumQuestions(qdcount);

    for (int i = 0; i < qdcount; i++)
    {
        DNSQuestion question;
        question.qname = name[i];
        question.qclass = dnsclass;
        question.qtype = type;

        // in this case we vary from standard implementations
        // questions are appended as array in DNSPacket
        q->setQuestions(i, question);
    }
    return q;
}

/**
 * @brief resolveQuery
 *      Extracts information in order to resolve a DNS query.
 */
struct Query* resolveQuery(cPacket *query)
{
    DNSPacket* v = dynamic_cast<DNSPacket*>(query);

    if (v == 0) // Bad .. not a DNSPacket!
    {
        throw E_NOT_A_DNSPACKET;
    }

    if(DNS_HEADER_QR(v->getOptions()) != 0){
        throw E_WRONG_QR;
    }

    struct Query* q = (Query*) malloc(sizeof(Query));

    // Parse v into q

    q->id = v->getId();
    q->qdcount = v->getQdcount();
    q->ancount = 0;
    q->nscount = 0;
    q->arcount = 0;

    DNSQuestion *questions = (DNSQuestion*) malloc(sizeof(DNSQuestion) * q->qdcount);
    for(short i = 0; i < q->qdcount; i++){
        questions[i] = v->getQuestions(i);
    }

    q->questions = questions;

    return q;
}

/**
 * @brief createResponse
 *      Creates a dns response header.
 */
DNSPacket* createResponse(char *msg_name, unsigned short ancount, unsigned short nscount, unsigned short arcount,
        unsigned short id, unsigned short opcode, unsigned short AA, unsigned short rd, unsigned short ra,
        unsigned short rcode)
{
    DNSPacket *r = new DNSPacket(msg_name);
    // Set id and options in header ..
    r->setId(id);
    r->setAncount(ancount);
    r->setNumAnswers(ancount);
    r->setNscount(nscount);
    r->setNumAuthorities(nscount);
    r->setArcount(arcount);
    r->setNumAdditional(arcount);

    unsigned short options = 0;
    DNS_HEADER_SET_QR(options, 1);
    // Opcode based on query..
    DNS_HEADER_SET_OPCODE(options, opcode);
    // Authoritative? Application should know ..
    DNS_HEADER_SET_AA(options, AA);
    // Recursion desired ..
    DNS_HEADER_SET_RD(options, rd);
    DNS_HEADER_SET_RA(options, ra);

    DNS_HEADER_SET_RCODE(options, rcode);

    // Append answers separately in another method

    return r;
}

/**
 * @brief appendAnswer
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAnswer(DNSPacket *p, int record_num, char *rname, unsigned short rtype, unsigned short rclass,
        unsigned int ttl, unsigned short rdlength, char *rdata)
{
    if (record_num < 0 || record_num > p->getAncount())
    {
        throw E_BAD_INDEX;
    }

    DNSRecord record;
    record.rname = rname;
    record.rtype = rtype;
    record.rclass = rclass;
    record.ttl = ttl;
    record.rdlength = rdlength;
    record.rdata = rdata;

    p->setAnswers(record_num, record);

    return 1;
}

/**
 * @brief appendAuthority
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAuthority(DNSPacket *p, int record_num, char *rname, unsigned short rtype, unsigned short rclass,
        unsigned int ttl, unsigned short rdlength, char *rdata)
{
    if (record_num < 0 || record_num > p->getNscount())
    {
        throw E_BAD_INDEX;
    }

    DNSRecord record;
    record.rname = rname;
    record.rtype = rtype;
    record.rclass = rclass;
    record.ttl = ttl;
    record.rdlength = rdlength;
    record.rdata = rdata;

    p->setAuthorities(record_num, record);

    return 1;
}

/**
 * @brief appendAdditional
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAdditional(DNSPacket *p, int record_num, char *rname, unsigned short rtype, unsigned short rclass,
        unsigned int ttl, unsigned short rdlength, char *rdata)
{
    if (record_num < 0 || record_num > p->getArcount())
    {
        throw E_BAD_INDEX;
    }

    DNSRecord record;
    record.rname = rname;
    record.rtype = rtype;
    record.rclass = rclass;
    record.ttl = ttl;
    record.rdlength = rdlength;
    record.rdata = rdata;

    p->setAdditional(record_num, record);

    return 1;
}

/**
 * @brief resolveResponse
 *      Extracts information in order to resolve a DNS response.
 */
struct Response* resolveResponse(cPacket *response)
{
    DNSPacket* v = dynamic_cast<DNSPacket*>(response);

    if (v == 0) // Bad .. not a DNSPacket!
    {
        throw E_NOT_A_DNSPACKET;
    }

    if(DNS_HEADER_QR(v->getOptions()) != 1){
        throw E_WRONG_QR;
    }

    struct Response* r = (Response*) malloc(sizeof(Response));

    // Parse v into q

    r->id = v->getId();
    r->qdcount = 0;
    r->ancount = v->getAncount();
    r->nscount = v->getNscount();
    r->arcount = v->getArcount();

    // Migrate Answers
    DNSRecord *answers = (DNSRecord*) malloc(sizeof(DNSRecord) * r->ancount);
    for(short i = 0; i < r->ancount; i++){
        answers[i] = v->getAnswers(i);
    }

    // Migrate Authoritative Records
    DNSRecord *authoritative = (DNSRecord*) malloc(sizeof(DNSRecord) * r->nscount);
    for(short i = 0; i < r->nscount; i++){
        authoritative[i] = v->getAuthorities(i);
    }

    // Migrate Additional Records
    DNSRecord *additional = (DNSRecord*) malloc(sizeof(DNSRecord) * r->arcount);
    for(short i = 0; i < r->arcount; i++){
        additional[i] = v->getAdditional(i);
    }

    r->answers = answers;
    r->authoritative = authoritative;
    r->additional = additional;

    return r;
}

/**
 * @brief isDNSPacket
 *      Determine whether p is a DNS packet
 *
 * @return
 *      0 false, 1 true
 */
int isDNSpacket(cPacket *p)
{
    // If p can be casted in to the original definition
    // then all is well.
    DNSPacket* v = dynamic_cast<DNSPacket*>(p);
    if (v != 0)
    {
        return 1;
    }
    return 0;
}

/**
 * @brief isQueryOrResponse
 *      Determine whether p is a query or response.
 *
 * @return
 *     -1 if not a DNS packet, 0 if Query, 1 if Response
 */
int isQueryOrResponse(cPacket *p)
{
    DNSPacket* v = dynamic_cast<DNSPacket*>(p);
    if (v != 0)
    {
        unsigned short o = v->getOptions();
        return DNS_HEADER_QR(o);
    }
    return -1;
}

} /* namespace ODnsExtension */

