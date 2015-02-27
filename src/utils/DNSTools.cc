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

#include <DNSTools.h>

namespace ODnsExtension {

const char* DNS_TYPE_ARRAY_ANY[13] = {"A", "NS", "CNAME", "SOA", "NULL", "PTR", "HINFO", "MINFO", "MX", "TXT", "AAAA", "SRV", "AXFR"};

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

    q->setOptions(options);

    return q;
}

/**
 * @brief createNQuery
 *      Creates a query with multiple questions
 */

DNSPacket* createNQuery(char *msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount, unsigned short arcount, unsigned short id, unsigned short rd)
{
    DNSPacket *q = new DNSPacket(msg_name);

    // Set id and options in header ..
    q->setId(id);
    q->setQdcount(qdcount);
    q->setAncount(ancount);
    q->setNscount(nscount);
    q->setArcount(arcount);

    unsigned short options = 0;
    // QR and OPCODE already 0..
    // Recursion desired ..
    DNS_HEADER_SET_RD(options, rd);

    // Setup question
    q->setNumQuestions(qdcount);

    q->setOptions(options);
    return q;
}

/**
 * @brief resolveQuery
 *      Extracts information in order to resolve a DNS query.
 */
struct Query* resolveQuery(cPacket* query)
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
    q->options = v->getOptions();

    DNSQuestion *questions = (DNSQuestion*) malloc(sizeof(*questions) * q->qdcount);
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
DNSPacket* createResponse(char *msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount, unsigned short arcount,
        unsigned short id, unsigned short opcode, unsigned short AA, unsigned short rd, unsigned short ra,
        unsigned short rcode)
{
    DNSPacket *r = new DNSPacket(msg_name);
    // Set id and options in header ..
    r->setId(id);
    r->setQdcount(qdcount);
    r->setNumQuestions(qdcount);
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

    r->setOptions(options);

    return r;
}

/**
 * @brief appendQuestion
 *      Appends a question to a previously generated DNS packet.
 */
int appendQuestion(DNSPacket *p, ODnsExtension::DNSQuestion *q, int index)
{
    p->setQuestions(index, *q);

    return 1;
}

/**
 * @brief appendAnswer
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAnswer(DNSPacket *p, ODnsExtension::DNSRecord *r, int index)
{
    p->setAnswers(index, *r);

    return 1;
}

/**
 * @brief appendAuthority
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAuthority(DNSPacket *p, ODnsExtension::DNSRecord *r, int index)
{
    p->setAuthorities(index, *r);

    return 1;
}

/**
 * @brief appendAdditional
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAdditional(DNSPacket *p, ODnsExtension::DNSRecord *r, int index)
{
    p->setAdditional(index, *r);

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

    // Append answers separately in another method



    // Parse v into q

    r->id = v->getId();
    r->qdcount = 0;
    r->ancount = v->getAncount();
    r->nscount = v->getNscount();
    r->arcount = v->getArcount();
    r->options = v->getOptions();

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

const char* getTypeStringForValue(int type){
    // init type

    const char* rtype;
    switch (type)
    {
        case DNS_TYPE_VALUE_A:
            rtype = DNS_TYPE_STR_A;
            break;
        case DNS_TYPE_VALUE_AAAA:
            rtype = DNS_TYPE_STR_AAAA;
            break;
        case DNS_TYPE_VALUE_CNAME:
            rtype = DNS_TYPE_STR_CNAME;
            break;
        case DNS_TYPE_VALUE_HINFO:
            rtype = DNS_TYPE_STR_HINFO;
            break;
        case DNS_TYPE_VALUE_MINFO:
            rtype = DNS_TYPE_STR_MINFO;
            break;
        case DNS_TYPE_VALUE_MX:
            rtype = DNS_TYPE_STR_MX;
            break;
        case DNS_TYPE_VALUE_NS:
            rtype = DNS_TYPE_STR_NS;
            break;
        case DNS_TYPE_VALUE_NULL:
            rtype = DNS_TYPE_STR_NULL;
            break;
        case DNS_TYPE_VALUE_PTR:
            rtype = DNS_TYPE_STR_PTR;
            break;
        case DNS_TYPE_VALUE_SOA:
            rtype = DNS_TYPE_STR_SOA;
            break;
        case DNS_TYPE_VALUE_TXT:
            rtype = DNS_TYPE_STR_TXT;
            break;
        case DNS_TYPE_VALUE_SRV:
            rtype = DNS_TYPE_STR_SRV;
            break;
        case DNS_TYPE_VALUE_ANY:
            rtype = DNS_TYPE_STR_ANY;
            break;
        case DNS_TYPE_VALUE_AXFR:
            rtype = DNS_TYPE_STR_AXFR;
            break;
    }

    return rtype;
}

/**
 * @brief getTypeStringForValue
 *      Get the given DNS_TYPE_VALUE value for a DNS_TYPE_STR
 *
 * @return
 *      the according type value. -1 if the type is not available.
 */
int getTypeValueForString(char* type){
    if(g_strcmp0(type, DNS_TYPE_STR_A) == 0) return DNS_TYPE_VALUE_A;
    if(g_strcmp0(type, DNS_TYPE_STR_AAAA) == 0) return DNS_TYPE_VALUE_AAAA;
    if(g_strcmp0(type, DNS_TYPE_STR_CNAME) == 0) return DNS_TYPE_VALUE_CNAME;
    if(g_strcmp0(type, DNS_TYPE_STR_HINFO) == 0) return DNS_TYPE_VALUE_HINFO;
    if(g_strcmp0(type, DNS_TYPE_STR_MINFO) == 0) return DNS_TYPE_VALUE_MINFO;
    if(g_strcmp0(type, DNS_TYPE_STR_MX) == 0) return DNS_TYPE_VALUE_MX;
    if(g_strcmp0(type, DNS_TYPE_STR_NS) == 0) return DNS_TYPE_VALUE_NS;
    if(g_strcmp0(type, DNS_TYPE_STR_NULL) == 0) return DNS_TYPE_VALUE_NULL;
    if(g_strcmp0(type, DNS_TYPE_STR_PTR) == 0) return DNS_TYPE_VALUE_PTR;
    if(g_strcmp0(type, DNS_TYPE_STR_SOA) == 0) return DNS_TYPE_VALUE_SOA;
    if(g_strcmp0(type, DNS_TYPE_STR_TXT) == 0) return DNS_TYPE_VALUE_TXT;
    if(g_strcmp0(type, DNS_TYPE_STR_SRV) == 0) return DNS_TYPE_VALUE_SRV;
    if(g_strcmp0(type, DNS_TYPE_STR_ANY) == 0) return DNS_TYPE_VALUE_ANY;
    if(g_strcmp0(type, DNS_TYPE_STR_AXFR) == 0) return DNS_TYPE_VALUE_AXFR;

    return -1;
}

/**
 * @brief getClassStringForValue
 *      Get the given DNS_CLASS_STR value for a DNS_CLASS
 *
 * @return
 *      the desired string value.
 */
const char* getClassStringForValue(int _class){
    const char* __class;

    switch (_class)
    {
        case DNS_CLASS_IN:
            __class = DNS_CLASS_STR_IN;
            break;
        case DNS_CLASS_CH:
            __class = DNS_CLASS_STR_CH;
            break;
        case DNS_CLASS_CS:
            __class = DNS_CLASS_STR_CS;
            break;
        case DNS_CLASS_HS:
            __class = DNS_CLASS_STR_HS;
            break;
        case DNS_CLASS_ANY:
            __class = DNS_CLASS_STR_ANY;
            break;
        default: break;
    }

    return __class;
}

void printDNSRecord(DNSRecord* r){
    g_printf("%s\t\t%s\t%s\t%s\n", r->rname, getTypeStringForValue(r->rtype), getClassStringForValue(r->rclass), r->rdata);
}

void printDNSQuestion(DNSQuestion* q){
    g_printf("%s\t\t%s\t%s\n", q->qname, getTypeStringForValue(q->qtype), getClassStringForValue(q->qclass));
}

/**
 * @brief freeDnsQuestion
 *      frees the given dns question
 * @return
 *      1 if successful
 *      0 otherwise
 */
int freeDnsQuestion(DNSQuestion* q){
    if(!q){
        return 0;
    }

    g_free(q->qname);
    free(q);

    return 1;
}

/**
 * @brief freeDnsRecord
 *      frees the given dns record
 * @return
 *      1 if successful
 *      0 otherwise
 */
int freeDnsRecord(DNSRecord* r){
    if(!r){
        return 0;
    }

    g_free(r->rname);
    g_free(r->rdata);
    free(r);

    return 1;
}

/**
 * @brief copyDnsRecord
 *  creates a hard-copy of a given dns record.
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
DNSRecord* copyDnsRecord(DNSRecord* r){
    DNSRecord* r_cpy = (DNSRecord*) malloc(sizeof(*r_cpy));
    r_cpy->rname = g_strdup(r->rname);
    r_cpy->rdata = g_strdup(r->rdata);
    r_cpy->rclass = r->rclass;
    r_cpy->rdlength = r->rdlength;
    r_cpy->rtype = r->rtype;
    r_cpy->ttl = r->ttl;

    return r_cpy;
}

/**
 * @brief copyDnsQuestion
 *  creates a hard-copy of a given dns question.
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
DNSQuestion* copyDnsQuestion(DNSQuestion* q){
    DNSQuestion* q_cpy = (DNSQuestion*) malloc(sizeof(*q_cpy));
    q_cpy->qname = g_strdup(q->qname);
    q_cpy->qtype = q->qtype;
    q_cpy->qclass = q->qclass;

    return q_cpy;
}

/**
 * @brief getTypeArray
 *      returns a type array with all DNS type strings
 */
const char** getTypeArray(){
    return DNS_TYPE_ARRAY_ANY;
}

} /* namespace ODnsExtension */

