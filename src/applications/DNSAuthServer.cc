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

#include "DNSAuthServer.h"

Define_Module(DNSAuthServer);

void DNSAuthServer::initialize()
{
    DNSServerBase::initialize();

    master_file = par("master_file").stdstringValue();

    // Use DNSZoneConfig
    config = new DNSZoneConfig();
    config->initialize(master_file);

    recursion_available = (int) par("recursion_available").doubleValue();

    response_count = 0;

}

void DNSAuthServer::handleMessage(cMessage *msg)
{
    DNSServerBase::handleMessage(msg);
}

DNSPacket* DNSAuthServer::handleQuery(ODnsExtension::Query *query)
{

    DNSPacket* response;
    if (query->qdcount > 1)
    {
        response = DNSServerBase::unsupportedOperation(query);
        return response;
    }

    ODnsExtension::DNSQuestion q;

    int id;
    int opcode;
    int rd;
    int ra;
    int an_records = 0;
    int ns_records = 0;
    int ar_records = 0;

    const char* __class;
    const char* type;

    char* namehash;
    char* nshash;
    char* cnhash;

    GList* answer_list = NULL;
    GList* ns_list = NULL;
    GList* ar_list = NULL;

    // initializes options
    id = query->id;

    opcode = DNS_HEADER_OPCODE(query->options);
    // recursion desired?
    rd = DNS_HEADER_RD(query->options);
    // recursion available
    ra = DNS_HEADER_RA(query->options);

    // Go through all questions and generate answers.
    q = query->questions[0];

    int is_authoritative = 0;
    std::string query_name = q.qname;
    int pos = query_name.find(config->getOrigin());

    // geerate msg name
    char *msg_name = (char*) malloc(20);
    sprintf(msg_name, "dns_response#%d", response_count++);

    if (pos != std::string::npos)
    {
        is_authoritative = 1;
    }

    // init class
    switch (q.qclass)
    {
        case DNS_CLASS_IN:
            __class = DNS_CLASS_STR_IN;
            break;
        case DNS_CLASS_CH:
        case DNS_CLASS_CS:
        case DNS_CLASS_HS:
        case DNS_CLASS_ANY:
        default:
            response = DNSServerBase::unsupportedOperation(query);
            return response;
    }

    // init type
    switch (q.qtype)
    {
        case DNS_TYPE_VALUE_A:
            type = DNS_TYPE_STR_A;
            break;
        case DNS_TYPE_VALUE_AAAA:
            type = DNS_TYPE_STR_AAAA;
            break;
        case DNS_TYPE_VALUE_CNAME:
            type = DNS_TYPE_STR_CNAME;
            break;
        case DNS_TYPE_VALUE_HINFO:
            response = DNSServerBase::unsupportedOperation(query);
            return response;
        case DNS_TYPE_VALUE_MINFO:
            type = DNS_TYPE_STR_MINFO;
            break;
        case DNS_TYPE_VALUE_MX:
            type = DNS_TYPE_STR_MX;
            break;
        case DNS_TYPE_VALUE_NS:
            type = DNS_TYPE_STR_NS;
            break;
        case DNS_TYPE_VALUE_NULL:
            response = DNSServerBase::unsupportedOperation(query);
            return response;
        case DNS_TYPE_VALUE_PTR:
            type = DNS_TYPE_STR_PTR;
            break;
        case DNS_TYPE_VALUE_SOA:
            type = DNS_TYPE_STR_SOA;
            break;
        case DNS_TYPE_VALUE_TXT:
            type = DNS_TYPE_STR_TXT;
            break;
        case DNS_TYPE_VALUE_SRV:
            type = DNS_TYPE_STR_SRV;
            break;
    }

    // now we can lookup the name in the database
    if (q.qtype == DNS_TYPE_VALUE_ANY)
    {
        // TODO: we need to find all records for either the class any statement
        // or the type..
    }
    else
    {
        // we have a specific record, so lets look it up in the hash table
        namehash = g_strdup_printf("%s:%s:%s", q.qname, type, __class);

        if (is_authoritative)
        {
            answer_list = appendEntries(namehash, answer_list, q.qtype, &an_records);
            g_free(namehash);

            // fill out authority section with NS records
            // if the request was on the ZONE ORIGIN
            // and it was not made for NS records.
            if (q.qtype != DNS_TYPE_VALUE_NS)
            {
                // get NS records
                nshash = g_strdup_printf("%s:%s:%s", config->getOrigin(), DNS_TYPE_STR_NS, __class);
                ns_list = appendEntries(nshash, ns_list, DNS_TYPE_VALUE_NS, &ns_records);
                g_free(nshash);
            }

            if(q.qtype != DNS_TYPE_VALUE_A && q.qtype != DNS_TYPE_VALUE_AAAA){
                ar_list = appendTransitiveEntries(answer_list, ar_list, DNS_TYPE_STR_A , DNS_TYPE_VALUE_A, &ar_records);
                ar_list = appendTransitiveEntries(answer_list, ar_list, DNS_TYPE_STR_AAAA , DNS_TYPE_VALUE_AAAA, &ar_records);
            }

            if(ns_records > 0){
                ar_list = appendTransitiveEntries(ns_list, ar_list, DNS_TYPE_STR_A , DNS_TYPE_VALUE_A, &ar_records);
                ar_list = appendTransitiveEntries(ns_list, ar_list, DNS_TYPE_STR_AAAA , DNS_TYPE_VALUE_AAAA, &ar_records);
            }

            // add CNAME if there are links for this label
            if(q.qtype != DNS_TYPE_VALUE_CNAME){
                // get NS records
                int old_an_records = an_records;
                cnhash = g_strdup_printf("%s:%s:%s", q.qname, DNS_TYPE_STR_CNAME, __class);
                answer_list = appendEntries(cnhash, answer_list, DNS_TYPE_VALUE_CNAME, &an_records);
                g_free(cnhash);

                // now we don't add the QTYPE record to additional, but to the answer section
                // iterate through the CNAME records, add the QTYPE records accordingly....
                int an_records_cpy = an_records; // since an_records is modified on the fly
                for(int i = old_an_records; i < an_records_cpy; i++){
                    DNSRecord* t_r = (DNSRecord*) g_list_nth(answer_list, i)->data;
                    // use the data string to create a hash and find the qtype record
                    char* namecpy = strdup(t_r->rdata);
                    cnhash = g_strdup_printf("%s.%s:%s:%s", namecpy, config->getOrigin(), type, __class);

                    // get entries for type using this hash
                    answer_list = appendEntries(cnhash, answer_list, q.qtype, &an_records);

                    g_free(cnhash);
                }
            }

            if(an_records == 0){ // no entry found, although authoritative
                response = ODnsExtension::createResponse(msg_name, 1, an_records, ns_records, ar_records, id, opcode,
                        1, rd, ra, 3);
            }
            else{
                response = ODnsExtension::createResponse(msg_name, 1, an_records, ns_records, ar_records, id, opcode,
                        1, rd, ra, 0);
            }
            response->setQuestions(0, q);

        }
        else
        {
            if (recursion_available)
            {
                if (rd)
                {
                    // TODO: Do recursion here!
                    if(an_records == 0){ // recursion desired, but no entry found
                        response = ODnsExtension::createResponse(msg_name, 1, an_records, ns_records, ar_records, id, opcode,
                                1, rd, ra, 3);
                    }
                    else{
                        response = ODnsExtension::createResponse(msg_name, 1, an_records, ns_records, ar_records, id, opcode,
                                1, rd, ra, 0);
                    }
                }
                else
                {
                    // response with not found err
                    response = ODnsExtension::createResponse(msg_name, 1, an_records, ns_records, ar_records, id, opcode,
                            1, rd, ra, 3);
                }

                // set question
                response->setQuestions(0, q);
            }
            else
            {
                response = DNSServerBase::unsupportedOperation(query);
                return response;
            }
        }
    }

    // append an, ns, ar to response
    int index = 0;

    if(an_records > 0){
        GList *next = g_list_first(answer_list);
        while(next){
            ODnsExtension::appendAnswer(response, (ODnsExtension::DNSRecord*) next->data, index++);

            next = g_list_next(next);
        }
        next = g_list_first(ns_list);
        index = 0;
        while(next){
            ODnsExtension::appendAuthority(response, (ODnsExtension::DNSRecord*) next->data, index++);

            next = g_list_next(next);
        }
        next = g_list_first(ar_list);
        index = 0;
        while(next){
            ODnsExtension::appendAdditional(response, (ODnsExtension::DNSRecord*) next->data, index++);

            next = g_list_next(next);
        }
    }
    else{
        // just append the SOA entry.
    }

    return response;

}

GList* DNSAuthServer::appendEntries(char *hash, GList *dstlist, int type, int *num_records)
{
    GList* entries = config->getEntry(hash);
    GList* next = g_list_first(entries);
    ODnsExtension::DNSRecord *rr;

    while (next)
    {
        zone_entry *entry = (zone_entry*) next->data;
        rr = (ODnsExtension::DNSRecord*) malloc(sizeof(*rr));
        rr->rdata = g_strdup(entry->data);
        rr->rname = g_strdup(entry->domain);
        rr->rclass = (short) DNS_CLASS_IN;
        rr->rtype = (short) type;
        rr->rdlength = strlen(rr->rdata);
        rr->ttl = config->getTTL();

        dstlist = g_list_append(dstlist, rr);
        (*num_records)++;

        // Check if transitive resolution is necessary:

        next = g_list_next(next);
    }
    return dstlist;
}

GList* DNSAuthServer::appendTransitiveEntries(GList *srclist, GList *dstlist, const char* DNS_TYPE_STR, int DNS_TYPE_VALUE, int *ar_records)
{
    GList *next = g_list_first(srclist);
    char* hash;

    // iterate through the source list
    while (next)
    {
        // get the zone entry
        zone_entry* record = (zone_entry*) next->data;

        // calculate hash from domain + type + class
        // first ar hash is for A records..
        hash = g_strdup_printf("%s:%s:%s", record->data, DNS_TYPE_STR, DNS_CLASS_STR_IN);

        GList* transitive_entries = config->getEntry(hash);
        g_free (hash);
        GList* t_next = g_list_first(transitive_entries);
        ODnsExtension::DNSRecord *dns_record;

        // go through
        while (t_next)
        {
            zone_entry *entry = (zone_entry*) t_next->data;
            dns_record = (ODnsExtension::DNSRecord*) malloc(sizeof(*dns_record));
            dns_record->rdata = g_strdup(entry->data);
            dns_record->rname = g_strdup(entry->domain);
            dns_record->rclass = (short) DNS_CLASS_IN;
            dns_record->rtype = (short) DNS_TYPE_VALUE;
            dns_record->rdlength = strlen(dns_record->rdata);
            dns_record->ttl = config->getTTL();

            dstlist = g_list_append(dstlist, dns_record);
            (*ar_records)++;

            t_next = g_list_next(t_next);
        }

        next = g_list_next(next);
    }

    return dstlist;
}
