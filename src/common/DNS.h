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

#ifndef DNS_H_
#define DNS_H_

#include <string>

/**
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 */
namespace ODnsExtension {

/**
 * Defining type values according to the RFC
 */
#define DNS_TYPE_VALUE_A        1
#define DNS_TYPE_VALUE_NS       2
#define DNS_TYPE_VALUE_CNAME    5
#define DNS_TYPE_VALUE_SOA      6
#define DNS_TYPE_VALUE_NULL     10
#define DNS_TYPE_VALUE_PTR      12
#define DNS_TYPE_VALUE_HINFO    13
#define DNS_TYPE_VALUE_MINFO    14
#define DNS_TYPE_VALUE_MX       15
#define DNS_TYPE_VALUE_TXT      16
#define DNS_TYPE_VALUE_AAAA     28
#define DNS_TYPE_VALUE_SRV      33

#define DNS_TYPE_STR_A          "A"
#define DNS_TYPE_STR_NS         "NS"
#define DNS_TYPE_STR_CNAME      "CNAME"
#define DNS_TYPE_STR_SOA        "SOA"
#define DNS_TYPE_STR_NULL       "NULL"
#define DNS_TYPE_STR_PTR        "PTR"
#define DNS_TYPE_STR_HINFO      "HINFO"
#define DNS_TYPE_STR_MINFO      "MINFO"
#define DNS_TYPE_STR_MX         "MX"
#define DNS_TYPE_STR_TXT        "TXT"
#define DNS_TYPE_STR_AAAA       "AAAA"
#define DNS_TYPE_STR_SRV        "SRV"

/**
 * Only valid for QTYPE
 */
#define DNS_TYPE_VALUE_AXFR     252
#define DNS_TYPE_VALUE_ANY      255
#define DNS_TYPE_STR_AXFR       "AXFR"
#define DNS_TYPE_STR_ANY        "ANY"

/**
 * DNS Classes
 */
#define DNS_CLASS_IN    1
#define DNS_CLASS_CS    2
#define DNS_CLASS_CH    3
#define DNS_CLASS_HS    4
#define DNS_CLASS_ANY   255

#define DNS_CLASS_STR_IN    "IN"
#define DNS_CLASS_STR_CS    "CS"
#define DNS_CLASS_STR_CH    "CH"
#define DNS_CLASS_STR_HS    "HS"
#define DNS_CLASS_STR_ANY   "ANY"

// Some other useful definitions
#define DNS_PORT 53

struct Query {
    unsigned short id;
    unsigned short options;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;

    // Questions from the query
    struct DNSQuestion* questions;

    std::string src_address;

    Query() :
            id(0), options(0), qdcount(0), ancount(0), nscount(0), arcount(0), questions(
                    NULL), src_address(NULL) {
    }

    Query(unsigned short _id, unsigned short _options, unsigned short _qdcount,
            unsigned short _ancount, unsigned short _nscount,
            unsigned short _arcount, DNSQuestion* _questions,
            std::string _src_address) :
            id(_id), options(_options), qdcount(_qdcount), ancount(_ancount), nscount(
                    _nscount), arcount(_arcount), questions(_questions), src_address(
                    _src_address) {
    }

};

struct DNSQuestion {
    /*
     * Domain name consisting of a sequence of labels.
     */
    std::string qname;
    /*
     * Two octet code specifying type of the query.
     */
    unsigned short qtype;
    /*
     * Two octect code specifying type of the query.
     */
    unsigned short qclass;

    DNSQuestion() :
            qname(NULL), qtype(0), qclass(0) {
    }

    DNSQuestion(std::string _qname, unsigned short _qtype,
            unsigned short _qclass) :
            qname(_qname), qtype(_qtype), qclass(_qclass) {
    }
};

struct Response {
    unsigned short id;
    unsigned short options;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;

    // Answers from the query
    struct DNSRecord* answers;
    struct DNSRecord* authoritative;
    struct DNSRecord* additional;

    Response() :
            id(0), options(0), qdcount(0), ancount(0), nscount(0), arcount(0), answers(
                    NULL), authoritative(NULL), additional(NULL) {
    }

    Response(unsigned short _id, unsigned short _options,
            unsigned short _qdcount, unsigned short _ancount,
            unsigned short _nscount, unsigned short _arcount,
            DNSRecord* _answers, DNSRecord* _authoritative,
            DNSRecord* _additional) :
            id(_id), options(_options), qdcount(_qdcount), ancount(_ancount), nscount(
                    _nscount), arcount(_arcount), answers(_answers), authoritative(
                    _authoritative), additional(_additional) {
    }
};

/**
 * Define different structs for the datatypes used in the domain name system
 */
struct SRVData {
    std::string service;
    std::string proto;
    std::string name;
    std::string target;
    unsigned short ttl;
    unsigned short weight;
    unsigned short priority;
    unsigned short port;

    SRVData() :
            service(NULL), proto(NULL), name(NULL), target(NULL), ttl(0), weight(
                    0), priority(0), port(0) {
    }
    ;
};

struct DNSRecord {
    /*
     * Name of the domain name record.
     */
    std::string rname;
    /*
     * Two octet code specifying RR type.
     */
    unsigned short rtype;
    /*
     * Two octet code specifying the RData class.
     */
    unsigned short rclass;
    /*
     * 32-bit unsigned integer specifying how long
     * the record may be cached.
     */
    unsigned int ttl;
    /*
     * 16-bit unsigned integer specifying the length
     * in octets of the rdata section.
     */
    unsigned short rdlength;

    /*
     * Variable length string. Format is according to rtype
     * and rclass of this record.
     */
    void* rdata;

    std::string strdata;

    DNSRecord() :
            rname(NULL), rtype(0), rclass(0), ttl(0), rdlength(0), rdata(NULL), strdata(NULL) {
    }

    DNSRecord(std::string _rname, unsigned short _rtype, unsigned short _rclass,
            unsigned int _ttl, unsigned short _rdlength, void* _rdata, std::string _strdata) :
            rname(_rname), rtype(_rtype), rclass(_rclass), ttl(_ttl), rdlength(
                    _rdlength), rdata(_rdata), strdata(_strdata) {
    }

    ~DNSRecord() {
        if (rdata != NULL) {
            switch (rtype) { // TODO: Add cases if more complex data types arise
            case DNS_TYPE_VALUE_SRV:
                delete ((SRVData*) rdata);
                break;
            default:
                break;
            }
        }
    }
    ;
};

/**
 * MAKROS to get DNS flag options
 */
#define DNS_HEADER_QR(h)                ((h >> 15) & 0x1)
#define DNS_HEADER_OPCODE(h)            ((h >> 11) & 0xf)
#define DNS_HEADER_AA(h)                ((h >> 10) & 0x1)
#define DNS_HEADER_TC(h)                ((h >> 9) & 0x1)
#define DNS_HEADER_RD(h)                ((h >> 7) & 0x1)
#define DNS_HEADER_RA(h)                ((h >> 6) & 0x1)
#define DNS_HEADER_Z(h)                 ((h >> 4) & 0x7)
#define DNS_HEADER_RCODE(h)             (h & 0xf)

/**
 * MAKROS to set DNS flags in options
 */
#define DNS_HEADER_SET_QR(h, v)       (h |= (unsigned short)(((v) & 0x1) << 15))
#define DNS_HEADER_SET_OPCODE(h, v)   (h |= (unsigned short)(((v) & 0xf) << 11))
#define DNS_HEADER_SET_AA(h, v)       (h |= (unsigned short)(((v) & 0x1) << 10))
#define DNS_HEADER_SET_TC(h, v)       (h |= (unsigned short)(((v) & 0x1) << 9))
#define DNS_HEADER_SET_RD(h, v)       (h |= (unsigned short)(((v) & 0x1) << 7))
#define DNS_HEADER_SET_RA(h, v)       (h |= (unsigned short)(((v) & 0x1) << 6))
#define DNS_HEADER_SET_Z(h, v)        (h |= (unsigned short)(((v) & 0x7) << 4))
#define DNS_HEADER_SET_RCODE(h, v)    (h |= (unsigned short)((v) & 0xf))

}

#endif /* DNS_H_ */
