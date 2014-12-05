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

#ifndef DNSTOOLS_H_
#define DNSTOOLS_H_

/*
 * Place c-ares in /usr/local/include
 * If you don't want to do that place it somewhere else,
 * but change the path accordingly.
 */
#include "/usr/local/include/c-ares/ares_dns.h"

/*
 * Include omnetpp header
 */
#include <omnetpp.h>

namespace ODnsExtension {

/**
 * @brief DNSTools provides methods for creating
 * DNS queries and responses, as well resolving (parsing)
 * queries and responses.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 */

class DNSTools
{
    public:
        DNSTools();
        virtual ~DNSTools();

        /**
         * @brief createQuery
         *      Creates simple DNS Queries for exactly one question
         *      (usually used by dns clients).
         */
        cPacket* createQuery(char *name, int dnsclass, int type, unsigned short id, int rd);

        /**
         * @brief createNQuery
         *      Creates a query with multiple questions
         */

        cPacket* createNQuery(int qdcount, char **name, int dnsclass, int type, unsigned short id, int rd);

        /**
         * @brief resolveQuery
         *      Extracts information in order to resolve a DNS query.
         */
        Query resolveQuery(char **query);

        /**
         * @brief resolveResponse
         *      Extracts information in order to resolve a DNS response.
         */
        Response resolveResponse(char **response);

        /**
         * @brief isDNSPacket
         *      Determine whether p is a DNS packet
         *
         * @return
         *      0 false, 1 true
         */
        int isDNSpacket(cPacket *p);

        /**
         * @brief isQueryOrResponse
         *      Determine whether p is a query or response.
         *
         * @return
         *      0 if Query, 1 if Response
         */
        int isQueryOrResponse(cPacket *p);


    protected:

};

struct Query{
        int dnsclass;
        int type;
        unsigned short id;
        int rd;

        // Questions from the query
        Question* questions;
};

struct Response{
        int dnsclass;
        int type;
        unsigned short id;
        int rd;

        // Answers from the query
        Record* answers;
        Record* authoritative;
        Record* additional;
};

struct Record{
        // TODO: record specific data
};

struct Question{
        // TODO: question specific data
};

}

#endif /* DNSTOOLS_H_ */
