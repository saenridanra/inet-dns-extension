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
    int is_origin = 0;

    std::string query_name = q.qname;
    uint32_t pos = query_name.find(config->getOrigin());
    if (pos != std::string::npos)
    {
        if (pos == 0)
        {
            is_origin = 1;
        }
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
        namehash = (char*) malloc(strlen(q.qname) + strlen(type) + strlen(__class) + 3);
        strcpy(namehash, q.qname);
        strcat(namehash, ":");
        strcat(namehash, type);
        strcat(namehash, ":");
        strcat(namehash, __class);

        if (is_authoritative && config->hasEntry(namehash))
        {
            an_records = appendEntries(namehash, answer_list, q.qtype);
            free(namehash);

            // fill out authority section with NS records
            // if the request was on the ZONE ORIGIN
            // and it was not made for NS records.
            if (is_origin && q.qtype != DNS_TYPE_VALUE_NS)
            {
                // get NS records
                nshash = (char*) malloc(strlen(config->getOrigin()) + strlen(DNS_TYPE_STR_NS) + strlen(__class) + 3);
                strcpy(nshash, config->getOrigin());
                strcat(nshash, ":");
                strcat(nshash, DNS_TYPE_STR_NS);
                strcat(nshash, ":");
                strcat(nshash, __class);
                ns_records = appendEntries(nshash, ns_list, DNS_TYPE_VALUE_NS);
                free(nshash);
            }

            ar_records = appendTransitiveEntries(answer_list, ar_list);
            ar_records += appendTransitiveEntries(ns_list, ar_list);

            size_t msg_size = 13 + floor(log10(abs(response_count))) + 1;
            char *msg_name = (char*) malloc(msg_size + 1);
            sprintf(msg_name, "dns_response#%d", response_count);
            response = ODnsExtension::createResponse(msg_name, an_records, ns_records, ar_records, query->id, opcode,
                    1, rd, ra, 0);

        }
        else
        {
            if (recursion_available)
            {
                if (rd)
                {
                    // TODO: recursion desired: answer question recursively
                }
                else
                {
                    // TODO: no recursion desired, send a not found
                }
            }
            else
            {
                response = DNSServerBase::unsupportedOperation(query);
                return response;
            }
        }
    }

    // append an, ns, ar to response
    GList *next = g_list_first(answer_list);
    while(g_list_next(next)){
        ODnsExtension::appendAnswer(response, (ODnsExtension::DNSRecord*) next->data);
    }
    next = g_list_first(ns_list);
    while(g_list_next(next)){
        ODnsExtension::appendAuthority(response, (ODnsExtension::DNSRecord*) next->data);
    }
    next = g_list_first(ns_list);
    while(g_list_next(next)){
        ODnsExtension::appendAdditional(response, (ODnsExtension::DNSRecord*) next->data);
    }

    return response;

}

int DNSAuthServer::appendEntries(char *hash, GList *dstlist, int type)
{
    int num_records = 0;
    GList* entries = config->getEntry(hash);
    GList* next = g_list_first(entries);
    ODnsExtension::DNSRecord *rr;

    while (g_list_next(next))
    {
        zone_entry *entry = (zone_entry*) next->data;
        rr = (ODnsExtension::DNSRecord*) malloc(sizeof(*rr));
        rr->rdata = (char*) malloc(strlen(entry->data));
        memcpy(rr->rdata, entry->data, strlen(entry->data));
        rr->rname = (char*) malloc(strlen(entry->domain));
        memcpy(rr->rname, entry->domain, strlen(entry->domain));
        rr->rclass = (short) DNS_CLASS_IN;
        rr->rtype = (short) type;
        rr->rdlength = strlen(rr->rdata);
        rr->ttl = config->getTTL();

        dstlist = g_list_append(dstlist, rr);
        num_records++;

        // Check if transitive resolution is necessary:
    }
    return num_records;
}

int DNSAuthServer::appendTransitiveEntries(GList *srclist, GList *dstlist)
{
    GList *next = g_list_first(srclist);
    char* hash;
    int ar_records = 0;

    // iterate through the source list
    while (g_list_next(next))
    {
        // get the zone entry
        zone_entry* record = (zone_entry*) next->data;

        // calculate hash from domain + type + class
        // first ar hash is for A records..
        hash = (char*) malloc(strlen(record->domain) + strlen(DNS_TYPE_STR_A) + strlen(record->__class) + 2);
        strcpy(hash, record->domain);
        strcat(hash, ":");
        strcat(hash, DNS_TYPE_STR_A);
        strcat(hash, ":");
        strcat(hash, record->__class);

        GList* transitive_entries = config->getEntry(hash);
        free (hash);
        GList* t_next = g_list_first(transitive_entries);
        ODnsExtension::DNSRecord *dns_record;

        // go through
        while (g_list_next(t_next))
        {
            zone_entry *entry = (zone_entry*) t_next->data;
            dns_record = (ODnsExtension::DNSRecord*) malloc(sizeof(*dns_record));
            dns_record->rdata = (char*) malloc(strlen(entry->data));
            memcpy(dns_record->rdata, entry->data, strlen(entry->data));
            dns_record->rname = (char*) malloc(strlen(entry->domain));
            memcpy(dns_record->rname, entry->domain, strlen(entry->domain));
            dns_record->rclass = (short) DNS_CLASS_IN;
            dns_record->rtype = (short) DNS_TYPE_VALUE_A;
            dns_record->rdlength = strlen(dns_record->rdata);
            dns_record->ttl = config->getTTL();

            dstlist = g_list_append(dstlist, dns_record);
            ar_records++;
        }

        // now for AAAA records..
        hash = (char*) malloc(strlen(record->domain) + strlen(DNS_TYPE_STR_AAAA) + strlen(record->__class) + 2);
        strcpy(hash, record->domain);
        strcat(hash, ":");
        strcat(hash, DNS_TYPE_STR_AAAA);
        strcat(hash, ":");
        strcat(hash, record->__class);

        transitive_entries = config->getEntry(hash);
        free(hash);
        t_next = g_list_first(transitive_entries);

        while (g_list_next(t_next))
        {
            zone_entry *entry = (zone_entry*) t_next->data;
            dns_record = (ODnsExtension::DNSRecord*) malloc(sizeof(*dns_record));
            dns_record->rdata = (char*) malloc(strlen(entry->data));
            memcpy(dns_record->rdata, entry->data, strlen(entry->data));
            dns_record->rname = (char*) malloc(strlen(entry->domain));
            memcpy(dns_record->rname, entry->domain, strlen(entry->domain));
            dns_record->rclass = (short) DNS_CLASS_IN;
            dns_record->rtype = (short) DNS_TYPE_VALUE_AAAA;
            dns_record->rdlength = strlen(dns_record->rdata);
            dns_record->ttl = config->getTTL();

            dstlist = g_list_append(dstlist, dns_record);
            ar_records++;
        }

        next = g_list_next(next);

    }

    return ar_records;
}
