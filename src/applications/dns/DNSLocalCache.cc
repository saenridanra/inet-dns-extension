//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#include "DNSLocalCache.h"

Define_Module(DNSLocalCache);

void DNSLocalCache::initialize(int stage)
{
    DNSServerBase::initialize(stage);

    recursion_available = (int) par("recursion_available").doubleValue();

    DNSServerBase::queryCache = g_hash_table_new_full(g_int_hash, g_int_equal, free, NULL);
    DNSServerBase::queryAddressCache = g_hash_table_new_full(g_int_hash, g_int_equal, free, NULL);
    DNSServerBase::responseCache = new ODnsExtension::DNSTTLCache();

    response_count = 0;

}

void DNSLocalCache::handleMessage(cMessage *msg)
{
    DNSServerBase::handleMessage(msg);
}

DNSPacket* DNSLocalCache::handleQuery(ODnsExtension::Query *query)
{
    DNSPacket* response;
    ODnsExtension::DNSQuestion q;
    int id, opcode, rd, ra, an_records = 0,ns_records = 0, ar_records = 0;
    GList* answer_list = NULL, ns_list = NULL, ar_list = NULL;
    char* __class, type, msg_name, namehash;

    if (query->qdcount > 1)
    {
        response = DNSServerBase::unsupportedOperation(query);
        return response;
    }

    // initializes options
    id = query->id;

    opcode = DNS_HEADER_OPCODE(query->options);
    // recursion desired?
    rd = DNS_HEADER_RD(query->options);
    // recursion available
    ra = DNS_HEADER_RA(query->options);

    // Go through all questions and generate answers.
    q = query->questions[0];

    // generate msg name
    msg_name = (char*) malloc(20);
    sprintf(msg_name, "dns_response#%d", response_count++);

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
    // at the momemnt we only support A, AAAA and CNAME for local
    // cache for usage in combination with the echo server
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
        case DNS_TYPE_VALUE_MINFO:
        case DNS_TYPE_VALUE_MX:
        case DNS_TYPE_VALUE_NS:
        case DNS_TYPE_VALUE_NULL:
        case DNS_TYPE_VALUE_PTR:
        case DNS_TYPE_VALUE_SOA:
        case DNS_TYPE_VALUE_TXT:
        case DNS_TYPE_VALUE_SRV:
        case DNS_TYPE_VALUE_ANY:
        case DNS_TYPE_VALUE_AXFR:
            response = DNSServerBase::unsupportedOperation(query);
            return response;
    }

    if(q.qtype == DNS_TYPE_VALUE_A || q.qtype == DNS_TYPE_VALUE_AAAA){
        // we know we don't store A and AAAA records in the cache
        // i.e., check if we have a corresponding CNAME mapping in the
        // cache
        char* cnhash = NULL;
        char* cnhash = g_strdup_printf("%s.%s.%s", q.qname, type, __class);
        GList* hashes = responseCache->get_matching_hashes(cnhash);

        // walk through the hashes and initiate recursive queries TODO: what about multi queries?
        // we will get lists for every CNAME in the cache

    }
    else if(q.qtype == DNS_TYPE_VALUE_CNAME){
        // check cache directly for the CNAME entry
    }

    // check if entry is in cache
    if(g_str_has_suffix(q.qname, "."))
        namehash = g_strdup_printf("%s:%s:%s", q.qname, type, __class);
    else
        namehash = g_strdup_printf("%s.:%s:%s", q.qname, type, __class);

    answer_list = appendEntries(namehash, answer_list, q.qtype, &an_records);
    g_free(namehash);

    // we don't want to return the answers, we use them to ask the authority for the A record :)

    if (recursion_available)
    {
        if (rd)
        {
            // do the initial query towards a root server
            // pick at random
            int p = intrand(rootServers.size());
            DNSPacket *root_q = ODnsExtension::createQuery(msg_name, query->questions[0].qname, DNS_CLASS_IN,
                    query->questions[0].qtype, query->id, 1);

            out.sendTo(root_q, rootServers[p], DNS_PORT);

            return NULL; // so it is known that recursive resolving has been initiated

        }
        else
        {
            // response with not found err
            response = ODnsExtension::createResponse(msg_name, 1, an_records, ns_records, ar_records, id, opcode, 0,
                    rd, ra, 0);
        }

        // set question
        response->setQuestions(0, q);
    }
    else
    {
        //TODO; Iterative answer.
        response = DNSServerBase::unsupportedOperation(query);
        return response;
    }

    // append an, ns, ar to response
    int index = 0;
    GList *next = g_list_first(answer_list);

    if (an_records > 0)
    {
        while (next)
        {
            ODnsExtension::appendAnswer(response, (ODnsExtension::DNSRecord*) next->data, index++);

            next = g_list_next(next);
        }
    }
    if(ns_records > 0){
        next = g_list_first(ns_list);
        index = 0;
        while (next)
        {
            ODnsExtension::appendAuthority(response, (ODnsExtension::DNSRecord*) next->data, index++);

            next = g_list_next(next);
        }
    }
    if(ar_records > 0){
        next = g_list_first(ar_list);
        index = 0;
        while (next)
        {
            ODnsExtension::appendAdditional(response, (ODnsExtension::DNSRecord*) next->data, index++);

            next = g_list_next(next);
        }
    }
    if(an_records == 0 && ns_records == 0 && ar_records == 0)
    {
        // do nothing ..
    }

    return response;

}

GList* DNSLocalCache::appendAuthority(GList *ns_list, int *ns_records){
    char *nshash = g_strdup_printf("%s:%s:%s", config->getOrigin(), DNS_TYPE_STR_NS, DNS_CLASS_STR_IN);
    ns_list = appendEntries(nshash, ns_list, DNS_TYPE_VALUE_NS, ns_records);
    g_free(nshash);

    return ns_list;
}

GList* DNSLocalCache::appendAdditionals(GList* ns_list, GList *ar_list, int *ar_records){
    ar_list = appendTransitiveEntries(ns_list, ar_list,
    DNS_TYPE_STR_A, DNS_TYPE_VALUE_A, ar_records);
    ar_list = appendTransitiveEntries(ns_list, ar_list,
    DNS_TYPE_STR_AAAA, DNS_TYPE_VALUE_AAAA, ar_records);

    return ar_list;
}

GList* DNSLocalCache::appendEntries(char *hash, GList *dstlist, int type, int *num_records)
{
    GList* entries = config->getEntry(hash);
    GList* next = g_list_first(entries);
    ODnsExtension::DNSRecord *rr;

    while (next)
    {
        zone_entry *entry = (zone_entry*) next->data;
        rr = (ODnsExtension::DNSRecord*) malloc(sizeof(*rr));
        rr->rdata = g_strdup(entry->data);

        if (g_str_has_suffix(entry->domain, config->getOrigin()))
        {
            rr->rname = g_strdup(entry->domain);
        }
        else
        {
            rr->rname = g_strdup_printf("%s.%s", entry->domain, config->getOrigin());
        }

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

GList* DNSLocalCache::appendTransitiveEntries(GList *srclist, GList *dstlist, const char* DNS_TYPE_STR,
        int DNS_TYPE_VALUE, int *ar_records)
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
        hash = g_strdup_printf("%s:%s:%s", record->data, DNS_TYPE_STR,
        DNS_CLASS_STR_IN);

        GList* transitive_entries = config->getEntry(hash);
        g_free(hash);
        GList* t_next = g_list_first(transitive_entries);
        ODnsExtension::DNSRecord *dns_record;

        // go through
        while (t_next)
        {
            zone_entry *entry = (zone_entry*) t_next->data;
            dns_record = (ODnsExtension::DNSRecord*) malloc(sizeof(*dns_record));
            dns_record->rdata = g_strdup(entry->data);

            if (g_str_has_suffix(entry->domain, config->getOrigin()))
            {
                dns_record->rname = g_strdup(entry->domain);
            }
            else
            {
                dns_record->rname = g_strdup_printf("%s.%s", entry->domain, config->getOrigin());
            }

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
