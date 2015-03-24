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

#include "MDNS.h"

namespace ODnsExtension {

int isProbe(DNSPacket* p){
    return isQuery(p) && p->getNscount() > 0;
}

int isAnnouncement(DNSPacket* p){
    // TODO: check if it's an Announcement
    return 0;
}

int isQuery(DNSPacket* p){
    return !ODnsExtension::isQueryOrResponse(p);
}

int isResponse(DNSPacket* p){
    return ODnsExtension::isQueryOrResponse(p);
}

int isGoodbye(std::shared_ptr<DNSRecord> r){
    return r->ttl==0;
}

std::shared_ptr<MDNSKey> mdns_key_new(std::string name, int type, int _class){
    std::shared_ptr<MDNSKey> k(new MDNSKey());
    k->name = name;
    k->type = type;
    k->_class = _class;

    return k;
}

void mdns_key_free(std::shared_ptr<MDNSKey> key){
    key.reset();
}

int compareMDNSKey(std::shared_ptr<ODnsExtension::MDNSKey> key1, std::shared_ptr<ODnsExtension::MDNSKey> key2){
    if(key1 == key2) return 0;

    int comp = key1->name.compare(key2->name);

    if(comp != 0) return comp;
    if(key1->type > key2->type) return 1;
    else if(key1->type < key2->type) return -1;
    else if(key1->_class > key2->_class) return 1;
    else if(key1->_class < key2->_class) return -1;

    return 0;
}

int compareMDNSKeyANY(std::shared_ptr<ODnsExtension::MDNSKey> key1, std::shared_ptr<ODnsExtension::MDNSKey> key2){
    if(key1 == key2) return 0;

    int comp = key1->name.compare(key2->name);

    if(comp != 0) return comp;
    else if(key1->_class > key2->_class) return 1;
    else if(key1->_class < key2->_class) return -1;

    return 0;
}

std::shared_ptr<ODnsExtension::DNSQuestion> createQuestion(std::string name, unsigned short type, unsigned short _class){
    std::shared_ptr<ODnsExtension::DNSQuestion> q(new DNSQuestion());
    q->qname = name;
    q->qtype = type;
    q->qclass = _class;

    return q;

}

std::shared_ptr<ODnsExtension::DNSQuestion> createQuestionFromKey(std::shared_ptr<ODnsExtension::MDNSKey> key){
    std::shared_ptr<ODnsExtension::DNSQuestion> q(new DNSQuestion());
    q->qname = key->name;
    q->qtype = key->type;
    q->qclass = key->_class;

    return q;

}

}
