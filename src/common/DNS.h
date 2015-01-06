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

#ifndef DNS_H_
#define DNS_H_

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
#define DNS_TYPE_VALUE_MB       7
#define DNS_TYPE_VALUE_MG       8
#define DNS_TYPE_VALUE_MR       9
#define DNS_TYPE_VALUE_NULL     10
#define DNS_TYPE_VALUE_WKS      11
#define DNS_TYPE_VALUE_PTR      12
#define DNS_TYPE_VALUE_HINFO    13
#define DNS_TYPE_VALUE_MINFO    14
#define DNS_TYPE_VALUE_MX       15
#define DNS_TYPE_VALUE_TXT      16

/**
 * Only valid for QTYPE
 */
#define DNS_TYPE_VALUE_AXFR     252
#define DNS_TYPE_VALUE_MAILB    253
#define DNS_TYPE_VALUE_MAILA    254
#define DNS_TYPE_VALUE_ANY      255

/**
 * DNS Classes
 */
#define DNS_CLASS_IN    1
#define DNS_CLASS_CS    2
#define DNS_CLASS_CH    3
#define DNS_CLASS_HS    4
#define DNS_CLASS_ANY   255


// Some other useful definitions
#define DNS_PORT 53

struct Query
{
        unsigned short id;
        unsigned short options;
        unsigned short qdcount;
        unsigned short ancount;
        unsigned short nscount;
        unsigned short arcount;

        // Questions from the query
        struct DNSQuestion* questions;
};

struct DNSQuestion
{
        /*
         * Domain name consisting of a sequence of labels.
         */
        char *qname;
        /*
         * Two octet code specifying type of the query.
         */
        unsigned short qtype;
        /*
         * Two octect code specifying type of the query.
         */
        unsigned short qclass;
};

struct Response
{
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
};

struct DNSRecord
{
        /*
         * Name of the domain name record.
         */
        char *rname;
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
        char *rdata;
};

/**
 * MAKROS to get DNS flag options
 */
#define DNS_HEADER_QR(h)                ((h >> 7) & 0x1)
#define DNS_HEADER_OPCODE(h)            ((h >> 3) & 0xf)
#define DNS_HEADER_AA(h)                ((h >> 2) & 0x1)
#define DNS_HEADER_TC(h)                ((h >> 1) & 0x1)
#define DNS_HEADER_RD(h)                (h & 0x1)
#define DNS_HEADER_RA(h)                ((h >> 7) & 0x1)
#define DNS_HEADER_Z(h)                 ((h >> 4) & 0x7)
#define DNS_HEADER_RCODE(h)             (h & 0xf)

/**
 * MAKROS to set DNS flags in options
 */
#define DNS_HEADER_SET_QR(h, v)       (h |= (unsigned char)(((v) & 0x1) << 7))
#define DNS_HEADER_SET_OPCODE(h, v)   (h |= (unsigned char)(((v) & 0xf) << 3))
#define DNS_HEADER_SET_AA(h, v)       (h |= (unsigned char)(((v) & 0x1) << 2))
#define DNS_HEADER_SET_TC(h, v)       (h |= (unsigned char)(((v) & 0x1) << 1))
#define DNS_HEADER_SET_RD(h, v)       (h |= (unsigned char)((v) & 0x1))
#define DNS_HEADER_SET_RA(h, v)       (h |= (unsigned char)(((v) & 0x1) << 7))
#define DNS_HEADER_SET_Z(h, v)        (h |= (unsigned char)(((v) & 0x7) << 4))
#define DNS_HEADER_SET_RCODE(h, v)    (h |= (unsigned char)((v) & 0xf))

}

#endif /* DNS_H_ */
