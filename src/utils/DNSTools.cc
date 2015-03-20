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
DNSPacket* createQuery(std::string msg_name, std::string name, unsigned short dnsclass, unsigned short type, unsigned short id,
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
    DNSQuestion* question = new DNSQuestion(name, dnsclass, type);
    q->setQuestions(0, question); // in this case we vary from standard implementations
                                  // questions are appended as array in DNSPacket

    q->setOptions(options);

    return q;
}

/**
 * @brief createNQuery
 *      Creates a query with multiple questions
 */

DNSPacket* createNQuery(std::string msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount, unsigned short arcount, unsigned short id, unsigned short rd)
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
    q->setNumAnswers(ancount);
    q->setNumAuthorities(nscount);
    q->setNumAdditional(arcount);

    q->setOptions(options);
    return q;
}

/**
 * @brief resolveQuery
 *      Extracts information in order to resolve a DNS query.
 */
struct Query resolveQuery(cPacket* query)
{
    DNSPacket* v = dynamic_cast<DNSPacket*>(query);

    if (v == 0) // Bad .. not a DNSPacket!
    {
        throw E_NOT_A_DNSPACKET;
    }

    if(DNS_HEADER_QR(v->getOptions()) != 0){
        throw E_WRONG_QR;
    }

    DNSQuestion questions [q->qdcount];
    for(short i = 0; i < q->qdcount; i++){
        questions[i] = v->getQuestions(i);
    }

    q->questions = questions;

    struct Query* q = new Query(v->getId(), v->getOptions(), v->getQdcount(), 0, 0, 0, questions, NULL);

    return q;
}

/**
 * @brief createResponse
 *      Creates a dns response header.
 */
DNSPacket* createResponse(std::string msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount, unsigned short arcount,
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

    // Migrate Answers
    DNSRecord answers [v->getNumAnswers()];
    for(short i = 0; i < r->ancount; i++){
        answers[i] = v->getAnswers(i);
    }

    // Migrate Authoritative Records
    DNSRecord authoritative [v->getNumAuthorities()];
    for(short i = 0; i < r->nscount; i++){
        authoritative[i] = v->getAuthorities(i);
    }

    // Migrate Additional Records
    DNSRecord additional [v->getNumAdditional()];
    for(short i = 0; i < r->arcount; i++){
        additional[i] = v->getAdditional(i);
    }

    r->answers = answers;
    r->authoritative = authoritative;
    r->additional = additional;

    struct Response* r = new Response(v->getId(), v->getOptions(), v->getQdcount(), 0, 0, 0, answers, authoritative, additional);

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

std::string getTypeStringForValue(int type){
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

    return std::string(rtype);
}

/**
 * @brief getTypeStringForValue
 *      Get the given DNS_TYPE_VALUE value for a DNS_TYPE_STR
 *
 * @return
 *      the according type value. -1 if the type is not available.
 */
int getTypeValueForString(std::string type){
    if(type == DNS_TYPE_STR_A) return DNS_TYPE_VALUE_A;
    if(type == DNS_TYPE_STR_AAAA) return DNS_TYPE_VALUE_AAAA;
    if(type == DNS_TYPE_STR_CNAME) return DNS_TYPE_VALUE_CNAME;
    if(type == DNS_TYPE_STR_HINFO) return DNS_TYPE_VALUE_HINFO;
    if(type == DNS_TYPE_STR_MINFO) return DNS_TYPE_VALUE_MINFO;
    if(type == DNS_TYPE_STR_MX) return DNS_TYPE_VALUE_MX;
    if(type == DNS_TYPE_STR_NS) return DNS_TYPE_VALUE_NS;
    if(type == DNS_TYPE_STR_NULL) return DNS_TYPE_VALUE_NULL;
    if(type == DNS_TYPE_STR_PTR) return DNS_TYPE_VALUE_PTR;
    if(type == DNS_TYPE_STR_SOA) return DNS_TYPE_VALUE_SOA;
    if(type == DNS_TYPE_STR_TXT) return DNS_TYPE_VALUE_TXT;
    if(type == DNS_TYPE_STR_SRV) return DNS_TYPE_VALUE_SRV;
    if(type == DNS_TYPE_STR_ANY) return DNS_TYPE_VALUE_ANY;
    if(type == DNS_TYPE_STR_AXFR) return DNS_TYPE_VALUE_AXFR;

    return -1;
}

/**
 * @brief getClassStringForValue
 *      Get the given DNS_CLASS_STR value for a DNS_CLASS
 *
 * @return
 *      the desired string value.
 */
std::string getClassStringForValue(int _class){
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

    return std::string(__class);
}

void printDNSRecord(DNSRecord* r){
    std::cout << r->rname << "\t\t" << getTypeStringForValue(r->rtype) << "\t" << getClassStringForValue(r->rclass) << "\t" << r->rdata << std::endl;
}

void printDNSQuestion(DNSQuestion* q){
    std::cout << q->qname << "\t\t" << getTypeStringForValue(q->qtype) << "\t" << getClassStringForValue(q->qclass) << std::endl;
}


/**
 * @brief dnsPacketToString
 *
 * @return
 *      returns a char sequence representing the dnspacket
 */

std::string dnsPacketToString(DNSPacket* packet){
    std::string dns_string = "";

    dns_string.append(";;Question Section:\n");
    dns_string.append(packet->getQuestions(0).qname);
    dns_string.append(":");
    dns_string.append(getClassStringForValue(packet->getQuestions(0).qclass));
    dns_string.append(":");
    dns_string.append(getTypeStringForValue(packet->getQuestions(0).qtype));
    dns_string.append("\n");

    dns_string.append("\n;;Answer Section:\n");
    for(int i = 0; i < packet->getAncount(); i++){
        dns_string.append(packet->getAnswers(i).rname);
        dns_string.append(":");
        dns_string.append(getClassStringForValue(packet->getAnswers(i).rclass));
        dns_string.append(":");
        dns_string.append(getTypeStringForValue(packet->getAnswers(i).rtype));
        dns_string.append("\n");
    }

    dns_string.append("\n;;Authority Section:\n");
    for(int i = 0; i < packet->getNscount(); i++){
        dns_string.append(packet->getAuthorities(i).rname);
        dns_string.append(":");
        dns_string.append(getClassStringForValue(packet->getAuthorities(i).rclass));
        dns_string.append(":");
        dns_string.append(getTypeStringForValue(packet->getAuthorities(i).rtype));
        dns_string.append("\n");
    }

    dns_string.append("\n;;Additional Section:\n");
    for(int i = 0; i < packet->getArcount(); i++){
        dns_string.append(packet->getAdditional(i).rname);
        dns_string.append(":");
        dns_string.append(getClassStringForValue(packet->getAdditional(i).rclass));
        dns_string.append(":");
        dns_string.append(getTypeStringForValue(packet->getAdditional(i).rtype));
        dns_string.append("\n");
    }

    return dns_string;
}

/**
 * @brief estimateDnsPacketSize
 *
 * @return
 *      The size of the DNSPacket
 */

int estimateDnsPacketSize(DNSPacket* packet){
    int size = 12; // initial header size

    size += strlen(packet->getQuestions(0).qname) + 4; // name length + 4 bytes for type and class
    for(int i = 0; i < packet->getAncount(); i++){
        size += 5 + strlen(packet->getAnswers(i).rname) + strlen(packet->getAnswers(i).rdata);
    }
    for(int i = 0; i < packet->getNscount(); i++){
        size += 5 + strlen(packet->getAuthorities(i).rname) + strlen(packet->getAuthorities(i).rdata);
    }
    for(int i = 0; i < packet->getArcount(); i++){
        size += 5 + strlen(packet->getAdditional(i).rname) + strlen(packet->getAdditional(i).rdata);
    }

    return size;
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

    delete q;

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

    delete r;

    return 1;
}

/**
 * @brief copyDnsRecord
 *  creates a hard-copy of a given dns record.
 *
 * @return
 *      the hard-copy created, the struct should be deleted accordingly.
 */
DNSRecord* copyDnsRecord(DNSRecord* r){
    // hard-cpy void * data..

    void* cpy_data;
    switch(r->rtype){
        case DNS_TYPE_VALUE_SRV: // user the srv struct, containing service domain, name, port, weight, etc...
            SRVData* srv_cpy = new SRVData();
            srv_cpy->service = ((SRVData*) r->rdata)->service;
            srv_cpy->name = ((SRVData*) r->rdata)->name;
            srv_cpy->proto = ((SRVData*) r->rdata)->proto;
            srv_cpy->target = ((SRVData*) r->rdata)->target;
            srv_cpy->ttl = ((SRVData*) r->rdata)->ttl;
            srv_cpy->port = ((SRVData*) r->rdata)->port;
            srv_cpy->weight = ((SRVData*) r->rdata)->weight;
            srv_cpy->priority = ((SRVData*) r->rdata)->priority;
            break;
        default: cpy_data = std::string((const char*) r->rdata); // consider data to be of type const char*
            break;
    }

    DNSRecord* r_cpy = new DNSRecord(r->rname, r->rtype, r->rclass, r->ttl, r->rdlength, cpy_data);
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
    DNSQuestion* q_cpy = new DNSQuestion(q->qname, q->qtype, q->qclass);
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

