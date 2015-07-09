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

namespace INETDNS {

const char* DNS_TYPE_ARRAY_ANY[13] = { "A", "NS", "CNAME", "SOA", "NULL", "PTR", "HINFO", "MINFO", "MX", "TXT", "AAAA",
        "SRV", "AXFR" };

/**
 * @brief createQuery
 *      Creates simple DNS Queries for exactly one question
 *      (usually used by dns clients).
 */
DNSPacket* createQuery(std::string msg_name, std::string name, unsigned short dnsclass, unsigned short type,
        unsigned short id, unsigned short rd)
{
    DNSPacket* q = new DNSPacket(msg_name.c_str());

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
    q->setQuestions(0, DNSQuestion(name, dnsclass, type)); // in this case we vary from standard implementations
    // questions are appended as array in DNSPacket

    q->setOptions(options);

    return q;
}

/**
 * @brief createNQuery
 *      Creates a query with multiple questions
 */

DNSPacket* createNQuery(std::string msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount,
        unsigned short arcount, unsigned short id, unsigned short rd)
{
    DNSPacket* q = new DNSPacket(msg_name.c_str());

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
std::shared_ptr<Query> resolveQuery(cPacket* query)
{
    DNSPacket* v = dynamic_cast<DNSPacket*>(query);

    if (v == 0) // Bad .. not a DNSPacket!
    {
        throw E_NOT_A_DNSPACKET
        ;
    }

    if (DNS_HEADER_QR(v->getOptions()) != 0)
    {
        throw E_WRONG_QR
        ;
    }

    std::shared_ptr<Query> q = std::shared_ptr<Query>(new Query(v->getId(), v->getOptions(), v->getQdcount(), 0, 0, 0, ""));

    for (short i = 0; i < v->getQdcount(); i++)
    {
        q->questions.push_back(v->getQuestions(i));
    }

    return q;
}

/**
 * @brief createResponse
 *      Creates a dns response header.
 */
DNSPacket* createResponse(std::string msg_name, unsigned short qdcount, unsigned short ancount, unsigned short nscount,
        unsigned short arcount, unsigned short id, unsigned short opcode, unsigned short AA, unsigned short rd,
        unsigned short ra, unsigned short rcode)
{
    DNSPacket* r = new DNSPacket(msg_name.c_str());
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
int appendQuestion(DNSPacket* p, std::shared_ptr<DNSQuestion> q, int index)
{
    p->setQuestions(index, *q);

    return 1;
}

/**
 * @brief appendAnswer
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAnswer(DNSPacket* p, std::shared_ptr<DNSRecord> r, int index)
{
    p->setAnswers(index, *r);

    return 1;
}

/**
 * @brief appendAuthority
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAuthority(DNSPacket* p, std::shared_ptr<DNSRecord> r, int index)
{
    p->setAuthorities(index, *r);

    return 1;
}

/**
 * @brief appendAdditional
 *      Appends an answer to a previously generated DNS packet.
 */
int appendAdditional(DNSPacket* p, std::shared_ptr<DNSRecord> r, int index)
{
    p->setAdditional(index, *r);

    return 1;
}

/**
 * @brief resolveResponse
 *      Extracts information in order to resolve a DNS response.
 */
std::shared_ptr<Response> resolveResponse(cPacket* response)
{
    DNSPacket* v = dynamic_cast<DNSPacket*>(response);

    if (v == 0) // Bad .. not a DNSPacket!
    {
        throw E_NOT_A_DNSPACKET
        ;
    }

    if (DNS_HEADER_QR(v->getOptions()) != 1)
    {
        throw E_WRONG_QR
        ;
    }

    std::shared_ptr<Response> r = std::shared_ptr<Response>(
            new Response(v->getId(), v->getOptions(), v->getQdcount(), v->getAncount(), v->getNscount(),
                    v->getArcount()));

    // Migrate Answers
    for (short i = 0; i < v->getAncount(); i++)
    {
        r->answers.push_back(v->getAnswers(i));
    }

    // Migrate Authoritative Records
    DNSRecord authoritative[v->getNumAuthorities()];
    for (short i = 0; i < v->getNscount(); i++)
    {
        r->authoritative.push_back(v->getAuthorities(i));
    }

    // Migrate Additional Records
    DNSRecord additional[v->getNumAdditional()];
    for (short i = 0; i < v->getArcount(); i++)
    {
        r->additional.push_back(v->getAdditional(i));
    }

    return r;
}

/**
 * @brief isDNSPacket
 *      Determine whether p is a DNS packet
 *
 * @return
 *      0 false, 1 true
 */
int isDNSpacket(cPacket* p)
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
int isQueryOrResponse(cPacket* p)
{
    DNSPacket* v = dynamic_cast<DNSPacket*>(p);
    if (v != 0)
    {
        unsigned short o = v->getOptions();
        return DNS_HEADER_QR(o);
    }
    return -1;
}

std::string getTypeStringForValue(int type)
{
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
int getTypeValueForString(std::string type)
{
    if (type == DNS_TYPE_STR_A)
        return DNS_TYPE_VALUE_A;
    if (type == DNS_TYPE_STR_AAAA)
        return DNS_TYPE_VALUE_AAAA;
    if (type == DNS_TYPE_STR_CNAME)
        return DNS_TYPE_VALUE_CNAME;
    if (type == DNS_TYPE_STR_HINFO)
        return DNS_TYPE_VALUE_HINFO;
    if (type == DNS_TYPE_STR_MINFO)
        return DNS_TYPE_VALUE_MINFO;
    if (type == DNS_TYPE_STR_MX)
        return DNS_TYPE_VALUE_MX;
    if (type == DNS_TYPE_STR_NS)
        return DNS_TYPE_VALUE_NS;
    if (type == DNS_TYPE_STR_NULL)
        return DNS_TYPE_VALUE_NULL;
    if (type == DNS_TYPE_STR_PTR)
        return DNS_TYPE_VALUE_PTR;
    if (type == DNS_TYPE_STR_SOA)
        return DNS_TYPE_VALUE_SOA;
    if (type == DNS_TYPE_STR_TXT)
        return DNS_TYPE_VALUE_TXT;
    if (type == DNS_TYPE_STR_SRV)
        return DNS_TYPE_VALUE_SRV;
    if (type == DNS_TYPE_STR_ANY)
        return DNS_TYPE_VALUE_ANY;
    if (type == DNS_TYPE_STR_AXFR)
        return DNS_TYPE_VALUE_AXFR;

    return -1;
}

/**
 * @brief getClassStringForValue
 *      Get the given DNS_CLASS_STR value for a DNS_CLASS
 *
 * @return
 *      the desired string value.
 */
std::string getClassStringForValue(int _class)
{
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
        default:
            break;
    }

    return std::string(__class);
}

void printDNSRecord(std::shared_ptr<DNSRecord> r)
{
    if (r->rtype == DNS_TYPE_VALUE_SRV)
        std::cout << r->rname << "\t\t" << getTypeStringForValue(r->rtype) << "\t" << getClassStringForValue(r->rclass)
                << "\t" << r->rdata << std::endl;
    else
        std::cout << r->rname << "\t\t" << getTypeStringForValue(r->rtype) << "\t" << getClassStringForValue(r->rclass)
                << "\t" << r->strdata << std::endl;
}

void printDNSQuestion(std::shared_ptr<DNSQuestion> q)
{
    std::cout << q->qname << "\t\t" << getTypeStringForValue(q->qtype) << "\t" << getClassStringForValue(q->qclass)
            << std::endl;
}

/**
 * @brief dnsPacketToString
 *
 * @return
 *      returns a char sequence representing the dnspacket
 */

std::string dnsPacketToString(DNSPacket* packet)
{
    std::string dns_string = "";

    dns_string.append(";;Question Section:\n");
    for (int i = 0; i < packet->getQdcount(); i++)
    {
        dns_string.append(packet->getQuestions(i).qname);
        dns_string.append(":");
        dns_string.append(getClassStringForValue(packet->getQuestions(i).qclass));
        dns_string.append(":");
        dns_string.append(getTypeStringForValue(packet->getQuestions(i).qtype));
        dns_string.append("\n");
    }

    dns_string.append(";;Answer Section:\n");
    for (int i = 0; i < packet->getAncount(); i++)
    {
        dns_string.append(packet->getAnswers(i).rname);
        dns_string.append(":");
        dns_string.append(getClassStringForValue(packet->getAnswers(i).rclass));
        dns_string.append(":");
        dns_string.append(getTypeStringForValue(packet->getAnswers(i).rtype));
        dns_string.append("\n");
    }

    dns_string.append(";;Authority Section:\n");
    for (int i = 0; i < packet->getNscount(); i++)
    {
        dns_string.append(packet->getAuthorities(i).rname);
        dns_string.append(":");
        dns_string.append(getClassStringForValue(packet->getAuthorities(i).rclass));
        dns_string.append(":");
        dns_string.append(getTypeStringForValue(packet->getAuthorities(i).rtype));
        dns_string.append("\n");
    }

    dns_string.append(";;Additional Section:\n");
    for (int i = 0; i < packet->getArcount(); i++)
    {
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
 * Helper method to tokenize a label string by "." and
 * check the size.
 */
int tokenizeAndGetSize(std::string s, std::unordered_map<std::string, bool> * ncm){
    int size = 0;
    std::vector<std::string> tokens = cStringTokenizer(s.c_str(), ".").asVector();
    // check if a token is in the hash map, otherwise put it there. only count characters
    // that are not in the map, the others only need the 2 offset bytes
    for (auto t : tokens)
    {
        if ((*ncm).find(t) != (*ncm).end())
            size += 2; // 2 bytes for the offset
        else
        {
            (*ncm)[t] = true; // add the bytes for the string
            size += t.length();
            if (tokens[tokens.size() - 1] != t)
                size++; // not the last token, add +1 for the dot
        }
    }

    return size;
}

/**
 * @brief estimateDnsPacketSize
 *
 * @return
 *      The size of the DNSPacket
 */
int estimateDnsPacketSize(DNSPacket* packet)
{
    int size = 12; // initial header size

    // map for name compression
    std::unordered_map<std::string, bool> ncm;
    for (int i = 0; i < packet->getQdcount(); i++)
    {
        size += tokenizeAndGetSize(packet->getQuestions(i).qname, &ncm);
        size += 4; // + 4 bytes for type and class
    }
    for (int i = 0; i < packet->getAncount(); i++)
    {
        if (packet->getAnswers(i).rtype != DNS_TYPE_VALUE_SRV)
        {
            size += tokenizeAndGetSize(packet->getAnswers(i).rname, &ncm);
            size += 10 + packet->getAnswers(i).strdata.length(); // no name compression for data
        }
        else
        {
            std::shared_ptr<SRVData> s = std::static_pointer_cast < SRVData > (packet->getAnswers(i).rdata);

            if (ncm.find(s->service) != ncm.end())
                size += 2;
            else
            {
                ncm[s->service] = true;
                size += s->service.length();
            }

            if (ncm.find(s->proto) != ncm.end())
                size += 2;
            else
            {
                ncm[s->proto] = true;
                size += s->proto.length();
            }

            size += tokenizeAndGetSize(s->name, &ncm);
            size += 16 + s->target.length();
        }
    }
    for (int i = 0; i < packet->getNscount(); i++)
    {
        if (packet->getAuthorities(i).rtype != DNS_TYPE_VALUE_SRV)
        {
            size += tokenizeAndGetSize(packet->getAuthorities(i).rname, &ncm);
            size += 10 + packet->getAuthorities(i).strdata.length();
        }
        else
        {
            std::shared_ptr<SRVData> s = std::static_pointer_cast < SRVData > (packet->getAuthorities(i).rdata);

            if (ncm.find(s->service) != ncm.end())
                size += 2;
            else
            {
                ncm[s->service] = true;
                size += s->service.length();
            }

            if (ncm.find(s->proto) != ncm.end())
                size += 2;
            else
            {
                ncm[s->proto] = true;
                size += s->proto.length();
            }

            size += tokenizeAndGetSize(s->name, &ncm);
            size += 16 + s->target.length();
        }
    }
    for (int i = 0; i < packet->getArcount(); i++)
    {
        if (packet->getAdditional(i).rtype != DNS_TYPE_VALUE_SRV)
        {
            size += tokenizeAndGetSize(packet->getAdditional(i).rname, &ncm);
            size += 10 + packet->getAdditional(i).strdata.length();
        }
        else
        {
            std::shared_ptr<SRVData> s = std::static_pointer_cast < SRVData > (packet->getAdditional(i).rdata);

            if (ncm.find(s->service) != ncm.end())
                size += 2;
            else
            {
                ncm[s->service] = true;
                size += s->service.length();
            }

            if (ncm.find(s->proto) != ncm.end())
                size += 2;
            else
            {
                ncm[s->proto] = true;
                size += s->proto.length();
            }

            size += tokenizeAndGetSize(s->name, &ncm);
            size += 16 + s->target.length();
        }
    }

    ncm.clear();

    return size;
}

/**
 * @brief freeDnsQuestion
 *      frees the given dns question
 * @return
 *      1 if successful
 *      0 otherwise
 */
int freeDnsQuestion(std::shared_ptr<DNSQuestion> q)
{
    if (!q)
    {
        return 0;
    }

    q.reset();

    return 1;
}

/**
 * @brief freeDnsRecord
 *      frees the given dns record
 * @return
 *      1 if successful
 *      0 otherwise
 */
int freeDnsRecord(std::shared_ptr<DNSRecord> r)
{
    if (!r)
    {
        return 0;
    }
    r.reset();

    return 1;
}

/**
 * @brief copyDnsRecord
 *  creates a hard-copy of a given dns record, referenced by a shared pointer.
 *
 * @return
 *      the hard-copy created, the struct should be deleted accordingly.
 */
std::shared_ptr<DNSRecord> copyDnsRecord(std::shared_ptr<DNSRecord> r)
{
    // hard-cpy void * data..

    std::shared_ptr<void> cpy_data;
    std::string strdata;
    switch (r->rtype)
    {
        case DNS_TYPE_VALUE_SRV: { // user the srv struct, containing service domain, name, port, weight, etc...
            std::shared_ptr<SRVData> srv_cpy(new SRVData());
            std::shared_ptr<INETDNS::SRVData> srv = std::static_pointer_cast < INETDNS::SRVData
                    > (r->rdata);
            srv_cpy->service = srv->service;
            srv_cpy->name = srv->name;
            srv_cpy->proto = srv->proto;
            srv_cpy->target = srv->target;
            srv_cpy->ttl = srv->ttl;
            srv_cpy->port = srv->port;
            srv_cpy->weight = srv->weight;
            srv_cpy->priority = srv->priority;

            cpy_data = std::static_pointer_cast<void>(srv_cpy);
            break;
        }
        default:
            strdata = std::string(r->strdata); // consider data to be of type const char*
            break;
    }

    std::shared_ptr<DNSRecord> r_cpy(
            new DNSRecord(r->rname, r->rtype, r->rclass, r->ttl, r->rdlength, cpy_data, strdata));
    return r_cpy;
}

/**
 * @brief copyDnsRecord
 *  creates a hard-copy of a given dns record.
 *
 * @return
 *      the hard-copy created, the struct should be deleted accordingly.
 */
std::shared_ptr<DNSRecord> copyDnsRecord(DNSRecord* r)
{
    // hard-cpy void * data..

    std::shared_ptr<void> cpy_data;
    std::string strdata;
    switch (r->rtype)
    {
        case DNS_TYPE_VALUE_SRV: { // user the srv struct, containing service domain, name, port, weight, etc...
            std::shared_ptr<SRVData> srv_cpy(new SRVData());

            std::shared_ptr<INETDNS::SRVData> srv = std::static_pointer_cast < INETDNS::SRVData
                    > (r->rdata);
            srv_cpy->service = srv->service;
            srv_cpy->name = srv->name;
            srv_cpy->proto = srv->proto;
            srv_cpy->target = srv->target;
            srv_cpy->ttl = srv->ttl;
            srv_cpy->port = srv->port;
            srv_cpy->weight = srv->weight;
            srv_cpy->priority = srv->priority;

            cpy_data = std::static_pointer_cast<void>(srv_cpy);
            break;
        }
        default:
            strdata = std::string(r->strdata); // consider data to be of type const char*
            break;
    }

    std::shared_ptr<DNSRecord> r_cpy = std::shared_ptr<DNSRecord>(
            new DNSRecord(r->rname, r->rtype, r->rclass, r->ttl, r->rdlength, cpy_data, strdata));
    return r_cpy;
}

/**
 * @brief copyDnsQuestion
 *  creates a hard-copy of a given dns question.
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSQuestion> copyDnsQuestion(std::shared_ptr<DNSQuestion> q)
{
    std::shared_ptr<DNSQuestion> q_cpy(new DNSQuestion(q->qname, q->qtype, q->qclass));
    return q_cpy;
}

/**
 * @brief copyDnsQuestion
 *  creates a hard-copy of a given dns question, given a shared pointer to the object.
 *
 * @return
 *      the hard-copy created, not that this needs to be freed if not used anymore.
 */
std::shared_ptr<DNSQuestion> copyDnsQuestion(DNSQuestion* q)
{
    std::shared_ptr<DNSQuestion> q_cpy(new DNSQuestion(q->qname, q->qtype, q->qclass));
    return q_cpy;
}

/**
 * @brief recordDataEqual
 *  compared rdata or strdata depending on type
 *  and checks if data is equal
 *
 * @return
 *      true if the records are equal
 */
int recordDataEqual(std::shared_ptr<DNSRecord> r1, std::shared_ptr<DNSRecord> r2)
{
    if (r1->rname != r2->rname && (r1->rtype != r2->rtype || r1->rclass != r2->rclass))
        return 0;

    switch (r1->rtype)
    {
        case DNS_TYPE_VALUE_SRV: {
            std::shared_ptr<SRVData> s1 = std::static_pointer_cast < SRVData > (r1->rdata);
            std::shared_ptr<SRVData> s2 = std::static_pointer_cast < SRVData > (r2->rdata);

            if (s1->name == s2->name && s1->port == s2->port && s1->priority == s2->priority && s1->proto == s2->proto
                    && s1->service == s2->service && s1->target == s2->target && s1->weight == s2->weight)
                return 1;
            break;
        }
        default: // compare str value
            return r1->strdata == r2->strdata;
    }

    return 0;

}

/**
 * @brief recordEqualNoData
 * compares records without comparing their data
 *
 * @return
 *      true if the records are equal (without data)
 */
int recordEqualNoData(std::shared_ptr<DNSRecord> r1, std::shared_ptr<DNSRecord> r2)
{
    if (r1->rname != r2->rname || (r1->rtype != r2->rtype || r1->rclass != r2->rclass))
        return 0;

    return 1;
}

/**
 * @brief getTypeArray
 *      returns a type array with all DNS type strings
 */
const char** getTypeArray()
{
    return DNS_TYPE_ARRAY_ANY;
}

} /* namespace ODnsExtension */

