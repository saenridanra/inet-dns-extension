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

#include <serializers/DNSSerializer.h>
#include <utils/Utils.h>
#include <cstringtokenizer.h>
#include "inet/networklayer/common/IPProtocolId_m.h"
#include <L3AddressResolver.h>

namespace inet {

namespace serializer {

Register_Serializer(DNSPacket, UNKNOWN, 0, DNSSerializer);

void DNSSerializer::serialize(const cPacket *_pkt, Buffer &b, Context& c) {
    // Make sure buffer cursor points to the start
    ASSERT(b.getPos() == 0);

    // Serialize header information for DNSPacket
    const DNSPacket* dnspk = check_and_cast<const DNSPacket *>(_pkt);
    //write id, options, qdcount, ancount, nscount and arcount
    b.writeUint16((uint16_t) dnspk->getId());
    b.writeUint16((uint16_t) dnspk->getOptions());
    b.writeUint16((uint16_t) dnspk->getQdcount());
    b.writeUint16((uint16_t) dnspk->getAncount());
    b.writeUint16((uint16_t) dnspk->getNscount());
    b.writeUint16((uint16_t) dnspk->getArcount());

    // write out questions
    for (int i = 0; i < dnspk->getQdcount(); i++) {
        INETDNS::DNSQuestion q = dnspk->getQuestions(i);
        serialize_question(&q, b);
    }

    // write out answers
    for (int i = 0; i < dnspk->getAncount(); i++) {
        INETDNS::DNSRecord r = dnspk->getAnswers(i);
        serialize_answer(&r, b);
    }
    // write out authorities
    for (int i = 0; i < dnspk->getNscount(); i++) {
        INETDNS::DNSRecord r = dnspk->getAuthorities(i);
        serialize_answer(&r, b);
    }
    // write out additionals
    for (int i = 0; i < dnspk->getArcount(); i++) {
        INETDNS::DNSRecord r = dnspk->getAdditional(i);
        serialize_answer(&r, b);
    }

    label_offsets.clear();

}

cPacket *DNSSerializer::deserialize(const Buffer &b, Context& c) {
    // Make sure buffer cursor points to the start
    ASSERT(b.getPos() == 0);
}

void DNSSerializer::serialize_question(INETDNS::DNSQuestion *question,
        Buffer &b) {
    // We write out questions in full label format
    serialize_name(question->qname, b, true);

    // write QTYPE and QCLASS
    b.writeUint16((uint16_t) question->qtype);
    b.writeUint16((uint16_t) question->qclass);
}

void DNSSerializer::serialize_answer(INETDNS::DNSRecord *record, Buffer &b) {
    // Check if there exists a label
    serialize_name(record->rname, b, true);

    // Write type, class, ttl, rdlength
    b.writeUint16((uint16_t) record->rtype);
    b.writeUint16((uint16_t) record->rclass);
    b.writeUint32((uint32_t) record->ttl);

    // Write RDATA
    if (record->rtype == DNS_TYPE_VALUE_SRV) {
        std::shared_ptr<INETDNS::SRVData> s = std::static_pointer_cast
                < INETDNS::SRVData > (record->rdata);

        // ttl, class, priority, weight, port and target.
        int curr_pos = b.getPos();
        b.seek(curr_pos + 2);
        b.writeUint16((uint16_t) s->priority);
        b.writeUint16((uint16_t) s->weight);
        b.writeUint16((uint16_t) s->port);
        serialize_name(s->target, b, false);
        // write rdlength (we only know it for sure, after
        // calculating the real length.
        int pos_after_data = b.getPos();
        b.seek(curr_pos);
        b.writeUint16((uint16_t) pos_after_data - curr_pos - 2);
        b.seek(pos_after_data);

    } else if (record->rtype == DNS_TYPE_VALUE_A) {
        // need to interpret the IPv4 address
        b.writeUint16((uint16_t) 4);

        IPv4Address ipv4addr = IPv4Address(record->strdata.c_str());
        b.writeUint32((uint32_t) ipv4addr.getInt());
    } else if (record->rtype == DNS_TYPE_VALUE_AAAA) {
        // need to interpret the IPv6 address
        b.writeUint16((uint16_t) 16);

        IPv6Address ipv6addr = IPv6Address(record->strdata.c_str());
        b.writeUint32((uint32_t) ipv6addr.words()[0]);
        b.writeUint32((uint32_t) ipv6addr.words()[1]);
        b.writeUint32((uint32_t) ipv6addr.words()[2]);
        b.writeUint32((uint32_t) ipv6addr.words()[3]);
    } else if (record->rtype == DNS_TYPE_VALUE_PTR
            || record->rtype == DNS_TYPE_VALUE_NS
            || record->rtype == DNS_TYPE_VALUE_CNAME) {
        // For now just write it out, but we need compression here as well
        int curr_pos = b.getPos();
        b.seek(curr_pos + 2);
        serialize_name(record->strdata, b, false);

        // write rdlength (we only know it for sure, after
        // calculating the real length.
        int pos_after_data = b.getPos();
        b.seek(curr_pos);
        b.writeUint16((uint16_t) pos_after_data - curr_pos - 2);
        b.seek(pos_after_data);
    } else if (record->rtype == DNS_TYPE_VALUE_TXT) {
        // no pointer check, just write the label
        b.writeUint16((uint16_t) record->strdata.length());
        serialize_data_string(record->strdata, b);
    } else {
        // Other types are currently not supported
    }
}

void DNSSerializer::serialize_name(std::string str, Buffer &b, bool is_name) {
    //
    // Serializing a name requires (example-name=www.uni-konstanz.de):
    //  Consuming the string until every dot, i.e.:
    //   www.uni-konstanz.de
    //   uni-konstanz.de
    //   de
    //  and remembering the offsets.
    //
    //  An answer could be uni-konstanz.de.
    //  in which case the 2byte pointer to the second
    //  string is used followed by a "." since that is not
    //  included in the string we pointed to
    //

    // first if there is a trailing .
    bool hasTrailingDot = false;
    bool labelUsed = false;
    if (INETDNS::stdstr_has_suffix(str, "."))
        hasTrailingDot = true;

    // first start with original string and consume
    cStringTokenizer tokenizer(str.c_str(), ".");
    std::vector<std::string> tokens = tokenizer.asVector();

    for (unsigned int i = 0; i < tokens.size(); i++) {
        // always combine tokens i to tokens.size() for lookup.
        std::string i_to_size;
        for (unsigned int j = i; j < tokens.size(); j++) {
            i_to_size += tokens[j];
            if (j != tokens.size() - 1)
                i_to_size += std::string(".");
        }

        // check if the label is already in the map (including the offset).

        if (label_offsets.find(i_to_size) != label_offsets.end()) {
            // if it is in the set, we can be sure that all
            // following labels have been included as well,
            // hence we can point to it and stop.
            unsigned short offset = label_offsets[i_to_size] | 0xC000;
            b.writeUint16((uint16_t) offset);
            labelUsed = true;
            break;
        } else {
            b.writeByte(0x3F & tokens[i].length());
            label_offsets[i_to_size] = (unsigned short) b.getPos() - 1;
            // write the string, if it's not the last add a dot
            // if it's the last add "0x00"
            for (unsigned char k = 0; k < i_to_size.length(); k++) {
                char curr_character = i_to_size.c_str()[k];
                if (curr_character == '.')
                    break; // stop, only write current label, next is to be consumed.
                b.writeByte(curr_character);
            }
        }

    }
    if(!labelUsed)
        b.writeByte(0x00); // end of name
}

void DNSSerializer::serialize_data_string(std::string str, Buffer &b) {
    unsigned short length = str.length();

    for (unsigned short i = 0; i < length; i++) {
        b.writeByte(str.c_str()[i]);
    }
    if(str.length() > 0)
        b.writeByte(0x00); // terminator string
}

}

}

