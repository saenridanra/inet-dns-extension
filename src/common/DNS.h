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
 * @file DNS.h
 *
 * Contains useful definitions of structs and makros needed for
 * a dns library.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */

#ifndef DNS_H_
#define DNS_H_

#include <string>
#include <vector>
#include <memory>

namespace INETDNS {

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
/**
 * Defining type strings for values
 */
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

/**
 * Standard DNS Port for UDP connections
 */
#define DNS_PORT 53

/**
 * @brief Struct representing a query
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
struct Query {

    /**
     * @brief The id of the query.
     */
    unsigned short id;

    /**
     * @brief Query options.
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * options is an 16 bit unsigned value used for setting query flags.
     */
    unsigned short options;

    /**
     * @brief Number of questions
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * qdcount is an 16 bit unsigned value denoting the amount of questions
     * in this query.
     */
    unsigned short qdcount;

    /**
     * @brief Number of answers
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * ancount is an 16 bit unsigned value denoting the amount of answers
     * in this query.
     */
    unsigned short ancount;

    /**
     * @brief Number of records in the authoritative section
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * nscount is an 16 bit unsigned value denoting the amount of records
     * int the authoritative section in this query.
     */
    unsigned short nscount;

    /**
     * @brief Number of records in the additonal section
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * nscount is an 16 bit unsigned value denoting the amount of records
     * int the additional section in this query.
     */
    unsigned short arcount;

    /**
     * @brief Array holding the questions for this query.
     */
    std::vector<struct DNSQuestion> questions;

    /**
     * @brief Source Address of the querier as a string.
     */
    std::string src_address;

    Query() :
            id(0), options(0), qdcount(0), ancount(0), nscount(0), arcount(0), src_address("") {
    }

    Query(unsigned short _id, unsigned short _options, unsigned short _qdcount,
            unsigned short _ancount, unsigned short _nscount,
            unsigned short _arcount, std::string _src_address) :
            id(_id), options(_options), qdcount(_qdcount), ancount(_ancount), nscount(
                    _nscount), arcount(_arcount), src_address(
                    _src_address) {
    }

};

/**
 * @brief Question as defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
struct DNSQuestion {

    /**
     * @brief Domain name consisting of a sequence of labels.
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>,
     * the query consists of a multiple of . separated labels.
     */
    std::string qname;

    /**
     * @brief Two octet code specifying type of the query.
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035>.
     */
    unsigned short qtype;

    /**
     * @brief Two octect code specifying type of the query.
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035>.
     */
    unsigned short qclass;

    DNSQuestion() :
            qname(""), qtype(0), qclass(0) {
    }

    DNSQuestion(std::string _qname, unsigned short _qtype,
            unsigned short _qclass) :
            qname(_qname), qtype(_qtype), qclass(_qclass) {
    }
};

/**
 * @brief Wrapper struct for dns responses
 *
 * holding all values define in RFC 1035 <http://tools.ietf.org/html/rfc1035>.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
struct Response {

    /**
     * @brief The id of the response.
     */
    unsigned short id;
    /**
     * @brief Query options.
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * options is an 16 bit unsigned value used for setting query flags.
     */
    unsigned short options;

    /**
     * @brief Number of questions
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * qdcount is an 16 bit unsigned value denoting the amount of questions
     * in this query.
     */
    unsigned short qdcount;

    /**
     * @brief Number of answers
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * ancount is an 16 bit unsigned value denoting the amount of answers
     * in this query.
     */
    unsigned short ancount;

    /**
     * @brief Number of records in the authoritative section
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * nscount is an 16 bit unsigned value denoting the amount of records
     * int the authoritative section in this query.
     */
    unsigned short nscount;

    /**
     * @brief Number of records in the additonal section
     *
     * As defined in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * nscount is an 16 bit unsigned value denoting the amount of records
     * int the additional section in this query.
     */
    unsigned short arcount;

    /**
     * @brief Array holding the answers for this response.
     */
    std::vector<struct DNSRecord> answers;

    /**
     * @brief Array holding the authoritative records for this response.
     */
    std::vector<struct DNSRecord> authoritative;

    /**
     * @brief Array holding the additional records for this response.
     */
    std::vector<struct DNSRecord> additional;

    Response() :
            id(0), options(0), qdcount(0), ancount(0), nscount(0), arcount(0) {
    }

    Response(unsigned short _id, unsigned short _options,
            unsigned short _qdcount, unsigned short _ancount,
            unsigned short _nscount, unsigned short _arcount) :
            id(_id), options(_options), qdcount(_qdcount), ancount(_ancount), nscount(
                    _nscount), arcount(_arcount) {
    }
};

/**
 * @brief Struct holding SRVData.
 *
 * According to the definition in RFC 2782 <https://www.ietf.org/rfc/rfc2782.txt>.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
struct SRVData {

    /**
     * @brief The symbolic name of the desired service
     *
     *   , as defined in Assigned Numbers [STD 2] or locally.  An underscore (_) is prepended to
     *   the service identifier to avoid collisions with DNS labels that
     *   occur in nature.
     *   Some widely used services, notably POP, don't have a single
     *   universal name.  If Assigned Numbers names the service
     *   indicated, that name is the only name which is legal for SRV
     *   lookups.  The Service is case insensitive.
     */
    std::string service;

    /**
     * @brief The symbolic name of the desired protocol
     *
     *   , with an underscore (_) prepended to prevent collisions with DNS labels that occur
     *   in nature.  _TCP and _UDP are at present the most useful values
     *   for this field, though any name defined by Assigned Numbers or
     *   locally may be used (as for Service).  The Proto is case
     *   insensitive.
     *
     *   @see RFC 2782 <https://www.ietf.org/rfc/rfc2782.txt>
     */
    std::string proto;

    /**
     * @brief The domain this RR refers to.
     *
     *  The SRV RR is unique in that the
     *  name one searches for is not this name; the example near the end
     *  shows this clearly.
     *
     *  @see RFC 2782 <https://www.ietf.org/rfc/rfc2782.txt>
     */
    std::string name;

    /**
     * @brief The domain name of the target host.
     *
     *   There MUST be one or more address records for this name, the name MUST NOT be an alias (in
     *   the sense of RFC 1034 or RFC 2181).  Implementors are urged, but
     *   not required, to return the address record(s) in the Additional
     *   Data section.  Unless and until permitted by future standards
     *   action, name compression is not to be used for this field.
     *
     *   A Target of "." means that the service is decidedly not
     *   available at this domain.
     *
     *   @see RFC 2782 <https://www.ietf.org/rfc/rfc2782.txt>
     */
    std::string target;

    /**
     * @brief Standard DNS meaning RFC 1035.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>
     * @see RFC 2782 <https://www.ietf.org/rfc/rfc2782.txt>
     */
    unsigned short ttl;

    /**
     * @brief A server selection mechanism.
     *
     *   The weight field specifies a
     *   relative weight for entries with the same priority. Larger
     *   weights SHOULD be given a proportionately higher probability of
     *   being selected. The range of this number is 0-65535.  This is a
     *   16 bit unsigned integer in network byte order.  Domain
     *   administrators SHOULD use Weight 0 when there isn't any server
     *   selection to do, to make the RR easier to read for humans (less
     *   noisy).  In the presence of records containing weights greater
     *   than 0, records with weight 0 should have a very small chance of
     *   being selected.
     *
     *   In the absence of a protocol whose specification calls for the
     *   use of other weighting information, a client arranges the SRV
     *   RRs of the same Priority in the order in which target hosts,
     *   specified by the SRV RRs, will be contacted. The following
     *   algorithm SHOULD be used to order the SRV RRs of the same
     *   priority:
     *
     *   To select a target to be contacted next, arrange all SRV RRs
     *   (that have not been ordered yet) in any order, except that all
     *   those with weight 0 are placed at the beginning of the list.
     *
     *   Compute the sum of the weights of those RRs, and with each RR
     *   associate the running sum in the selected order. Then choose a
     *   uniform random number between 0 and the sum computed
     *   (inclusive), and select the RR whose running sum value is the
     *   first in the selected order which is greater than or equal to
     *   the random number selected. The target host specified in the
     *   selected SRV RR is the next one to be contacted by the client.
     *   Remove this SRV RR from the set of the unordered SRV RRs and
     *   apply the described algorithm to the unordered SRV RRs to select
     *   the next target host.  Continue the ordering process until there
     *   are no unordered SRV RRs.  This process is repeated for each
     *   Priority.
     *
     * @see RFC 2782 <https://www.ietf.org/rfc/rfc2782.txt>
     */
    unsigned short weight;

    /**
     * @brief The priority of this target host.
     *
     *   A client MUST attempt to
     *   contact the target host with the lowest-numbered priority it can
     *   reach; target hosts with the same priority SHOULD be tried in an
     *   order defined by the weight field.  The range is 0-65535.  This
     *   is a 16 bit unsigned integer in network byte order.
     *
     *
     * @see RFC 2782 <https://www.ietf.org/rfc/rfc2782.txt>
     */
    unsigned short priority;

    /**
     * @brief The port on this target host of this service.
     *
     * The range is 0-65535.  This is a 16 bit unsigned integer in network byte order.
     * This is often as specified in Assigned Numbers but need not be.
     *
     * @see RFC 2782 <https://www.ietf.org/rfc/rfc2782.txt>
     */
    unsigned short port;

    SRVData() :
            service(""), proto(""), name(""), target(""), ttl(0), weight(0), priority(
                    0), port(0) {
    }
    ;
};

/**
 * @brief Struct holding RR Data
 *
 * According to the Definition in RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
struct DNSRecord {

    /**
     * @brief an owner name, i.e., the name of the node to which this esource record pertains.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    std::string rname;

    /**
     * @brief two octets containing one of the RR TYPE codes.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    unsigned short rtype;

    /**
     * @brief two octets containing one of the RR CLASS codes.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    unsigned short rclass;

    /**
     * @brief a 32 bit signed integer that specifies the time interval
     *
     *   that the resource record may be cached before the source
     *   of the information should again be consulted.  Zero
     *   values are interpreted to mean that the RR can only be
     *   used for the transaction in progress, and should not be
     *   cached.  For example, SOA records are always distributed
     *   with a zero TTL to prohibit caching.  Zero values can
     *   also be used for extremely volatile data.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    unsigned int ttl;

    /**
     * @brief an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    unsigned short rdlength;

    /**
     * @brief This void pointer stores more complex data structures, s.a. @ref ODnsExtension::SRVData
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    std::shared_ptr<void> rdata;

    /**
     * @brief a variable length string of octets that describes the resource.
     *
     *   The format of this information varies
     *   according to the TYPE and CLASS of the resource record.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    std::string strdata;

    DNSRecord() :
            rname(""), rtype(0), rclass(0), ttl(0), rdlength(0), rdata(NULL), strdata(
                    "") {
    }

    DNSRecord(std::string _rname, unsigned short _rtype, unsigned short _rclass,
            unsigned int _ttl, unsigned short _rdlength, std::shared_ptr<void> _rdata,
            std::string _strdata) :
            rname(_rname), rtype(_rtype), rclass(_rclass), ttl(_ttl), rdlength(
                    _rdlength), rdata(_rdata), strdata(_strdata) {
    }

    ~DNSRecord() {
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
