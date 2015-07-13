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
#include "inet/networklayer/common/IPProtocolId_m.h"
#include <L3AddressResolver.h>

namespace inet {

namespace serializer {

Register_Serializer(DNSPacket, IP_PROT, IP_PROT_UDP, DNSSerializer);

void DNSSerializer::serialize(const cPacket *_pkt, Buffer &b, Context& c){
    // Make sure buffer cursor points to the start
    ASSERT(b.getPos() == 0);

    // Serialize header information for DNSPacket
    const DNSPacket* dnspk = check_and_cast<const DNSPacket *> (_pkt->getEncapsulatedPacket());
    //write id, options, qdcount, ancount, nscount and arcount
    b.writeUint16(dnspk->getId());
    b.writeUint16(dnspk->getOptions());
    b.writeUint16(dnspk->getQdcount());
    b.writeUint16(dnspk->getAncount());
    b.writeUint16(dnspk->getNscount());
    b.writeUint16(dnspk->getArcount());

    // write out questions
    for(int i = 0; i < dnspk->getQdcount(); i++){
        INETDNS::DNSQuestion q = dnspk->getQuestions(i);
        serialize_question(&q, b);
    }

    // write out answers
    for(int i = 0; i < dnspk->getAncount(); i++){
        INETDNS::DNSRecord r = dnspk->getAnswers(i);
        serialize_answer(&r, b);
    }
    // write out authorities
    for(int i = 0; i < dnspk->getNscount(); i++){
        INETDNS::DNSRecord r = dnspk->getAuthorities(i);
        serialize_answer(&r, b);
    }
    // write out additionals
    for(int i = 0; i < dnspk->getArcount(); i++){
        INETDNS::DNSRecord r = dnspk->getAdditional(i);
        serialize_answer(&r, b);
    }

}

cPacket *DNSSerializer::deserialize(const Buffer &b, Context& c){
    // Make sure buffer cursor points to the start
    ASSERT(b.getPos() == 0);
}

void DNSSerializer::serialize_question(INETDNS::DNSQuestion *question, Buffer &b){
    // We write out questions in full label format
    if(label_offsets.find(question->qname) == label_offsets.end()){
        // Does not exist already so we save this offset in the map
        label_offsets[question->qname] = (unsigned short) b.getPos();
    }

    unsigned char length = question->qname.length();
    length &= 0x3F;

    b.writeByte(length);
    for(unsigned char i = 0; i < length; i++){
        b.writeByte(question->qname.c_str()[i]);
    }

    // write QTYPE and QCLASS
    b.writeUint16(question->qtype);
    b.writeUint16(question->qclass);
}

void DNSSerializer::serialize_answer(INETDNS::DNSRecord *record, Buffer &b){
    // Check if there exists a label
    serialize_name(record->rname, b);

    // Write type, class, ttl, rdlength
    b.writeUint16(record->rtype);
    b.writeUint16(record->rclass);
    b.writeUint32(record->ttl);
    b.writeUint16(record->rdlength);

    // Write RDATA
    if(record->rtype == DNS_TYPE_VALUE_SRV){
        std::shared_ptr<INETDNS::SRVData> s = std::static_pointer_cast < INETDNS::SRVData > (record->rdata);

        // do nothing for now..
    }
    else if (record->rtype == DNS_TYPE_VALUE_A){
        // need to interpret the IPv4 address
        IPv4Address ipv4addr = IPv4Address(record->strdata.c_str());
        b.writeUint32(ipv4addr.getInt());
    }
    else if (record->rtype == DNS_TYPE_VALUE_AAAA){
        // need to interpret the IPv6 address
        IPv6Address ipv6addr = IPv6Address(record->strdata.c_str());
        b.writeUint32(ipv6addr.words()[0]);
        b.writeUint32(ipv6addr.words()[1]);
        b.writeUint32(ipv6addr.words()[2]);
        b.writeUint32(ipv6addr.words()[3]);
    }
    else if (record->rtype == DNS_TYPE_VALUE_PTR || record->rtype == DNS_TYPE_VALUE_NS){
        // For now just write it out, but we need compression here as well
        serialize_data_string(record->strdata, b);
    }
    else if(record->rtype == DNS_TYPE_VALUE_TXT){
        // no pointer check, just write the label
        serialize_data_string(record->strdata, b);
    }
    else{
        // Other types are currently not supported
    }
}

void DNSSerializer::serialize_name(std::string str, Buffer &b){
    if(label_offsets.find(str) == label_offsets.end()){
        // Does not exist already so we save this offset in the map
        label_offsets[str] = (unsigned short) b.getPos();

        unsigned char length = str.length();
        length &= 0x3F;

        b.writeByte(length);
        for(unsigned char i = 0; i < length; i++){
            b.writeByte(str.c_str()[i]);
        }
    }
    else{
        // Label exists, create pointer
        unsigned short offset = label_offsets[str] | 0xA000;
        b.writeUint16(offset);
    }
}

void DNSSerializer::serialize_data_string(std::string str, Buffer &b){
    unsigned short length = str.length();

    for(unsigned short i = 0; i < length; i++){
        b.writeByte(str.c_str()[i]);
    }
}

}

}

