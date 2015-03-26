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

#include "DNSLocalCache.h"

Define_Module(DNSLocalCache);

void DNSLocalCache::initialize(int stage)
{
    DNSServerBase::initialize(stage);

    recursion_available = 1;
    response_count = 0;
    DNSServerBase::responseCache = new ODnsExtension::DNSTTLCache();

}

void DNSLocalCache::handleMessage(cMessage *msg)
{
    DNSServerBase::handleMessage(msg);
}

DNSPacket* DNSLocalCache::handleQuery(std::shared_ptr<ODnsExtension::Query> query)
{
    DNSPacket* response;
    ODnsExtension::DNSQuestion q;
    int id, opcode, rd, ra, an_records = 0,ns_records = 0, ar_records = 0, stop_cache_lookup = 0, rec_query_created = 0;
    std::list<std::shared_ptr<DNSRecord>> answer_list, ns_list, ar_list;
    const char* __class;
    const char* type;
    std::string msg_name, namehash;

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

    // Go through all questions and generate answers.
    q = query->questions[0];

    // generate msg name
    msg_name = std::string("dns_response#") + std::to_string(response_count++);

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
    // at the moment we only support A, AAAA for local
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

    // first check the cache
    if((q.qtype == DNS_TYPE_VALUE_A || q.qtype == DNS_TYPE_VALUE_AAAA) && responseCache){
        if (!rd || !recursion_available){
            // response with not found err, as recursion is not desired or not available
            // and we don't cache A records directly
            response = ODnsExtension::createResponse(msg_name, 1, an_records, ns_records, ar_records, id, opcode, 0,
                    rd, ra, 0);
            return response;
        }

        // we know we don't store A and AAAA records in the cache
        // i.e., check if we have a corresponding CNAME mapping in the
        // cache
        std::string cnhash = q.qname + std::string(":") + std::string(DNS_TYPE_STR_CNAME) + std::string(":") + std::string(__class);
        std::list<std::string> hashes = responseCache->get_matching_hashes(cnhash);

        // walk through the hashes and initiate recursive queries
        // for this simulation we can assume that we will only get one hash
        // for which there are no double entries in the cache

        for(auto it = hashes.begin(); it != hashes.end() && !stop_cache_lookup && !rec_query_created; ++it){
            // use the hash to get the corresponding entry
            std::string tmp = *it;
            // check if there is and entry in the cache, if so
            // we should follow it before querying
            std::list<std::shared_ptr<DNSRecord>> records;
            while(responseCache->is_in_cache(tmp)){
                // get the list of records from the cache
                records = responseCache->get_from_cache(tmp);
                // this list should not be greater than one, if it is
                // the cache may have been polluted, delete all entries
                // and do the normal iterative query

                if(records.size()  > 1){
                    responseCache->remove_from_cache(tmp);
                    stop_cache_lookup = 1;
                    break;
                }

                // only one record, extract data into tmp
                if((*(records.begin()))->rtype == DNS_TYPE_VALUE_CNAME){
                    tmp = (*(records.begin()))->strdata + std::string(":") + std::string(DNS_TYPE_STR_CNAME) + std::string(":") + std::string(DNS_CLASS_STR_IN);
                }
                else // end of chain but not a CNAME
                    break;
            }

            // if the flag is not set, we can use the record to perform our recursive query
            if(!stop_cache_lookup && rootServers.size() > 0){
                // the record is stored in *records
                std::shared_ptr<DNSRecord> end_of_chain_record = *(records.begin());
                // use the rdata in the record to create a recursive query
                int id = DNSServerBase::getIdAndInc();
                DNSServerBase::store_in_query_cache(id, query);
                msg_name = std::string("dns_query#") + std::to_string(id) + std::string("--recursive");

                int p = intrand(rootServers.size());
                DNSPacket *root_q = ODnsExtension::createQuery(msg_name, end_of_chain_record->strdata, DNS_CLASS_IN,
                        query->questions[0].qtype, id, 1);

                DNSServerBase::sendResponse(root_q, rootServers[p]);

                rec_query_created = 1;
            }
        }

        if(!stop_cache_lookup && rec_query_created) // there were no problems, recursive query was generated
            return NULL;

    }

    // if we get here, cache lookup was unsuccessful
    if (recursion_available && rootServers.size() > 0)
    {
        if (rd)
        {
            int id = DNSServerBase::getIdAndInc();
            DNSServerBase::store_in_query_cache(id, query);
            msg_name = std::string("dns_query#") + std::to_string(id) + std::string("--recursive");

            // do the initial query towards a root server
            // pick at random
            int p = intrand(rootServers.size());
            DNSPacket *root_q = ODnsExtension::createQuery(msg_name, query->questions[0].qname, DNS_CLASS_IN,
                    query->questions[0].qtype, id, 1);

            DNSServerBase::sendResponse(root_q, rootServers[p]);

            return NULL;

        }
        else
        {
            // response with not found err
            response = ODnsExtension::createResponse(msg_name, 1, an_records, ns_records, ar_records, id, opcode, 0,
                    rd, ra, 0);

            // set question
            response->setQuestions(0, q);
            return response;
        }
    }
    else
    {
        //TODO; Iterative answer.
        response = DNSServerBase::unsupportedOperation(query);
        return response;
    }

}
