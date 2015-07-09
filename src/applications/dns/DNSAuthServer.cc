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

void DNSAuthServer::initialize(int stage) {
    DNSServerBase::initialize(stage);
    if(stage == inet::INITSTAGE_APPLICATION_LAYER){
        master_file = par("master_file").stdstringValue();

        // Use DNSZoneConfig
        config = std::shared_ptr<DNSZoneConfig>(new DNSZoneConfig());
        config->initialize(master_file);

        recursion_available = (int) par("recursion_available").doubleValue();

        response_count = 0;
    }

}

void DNSAuthServer::handleMessage(cMessage *msg) {
    DNSServerBase::handleMessage(msg);
}

DNSPacket* DNSAuthServer::handleQuery(
        std::shared_ptr<INETDNS::Query> query) {

    DNSPacket* response;
    if (query->qdcount > 1) {
        response = DNSServerBase::unsupportedOperation(query);
        return response;
    }

    INETDNS::DNSQuestion q;

    int id, opcode, rd, ra;
    int an_records = 0, ns_records = 0, ar_records = 0;

    const char* __class, *type;
    std::string namehash, cnhash;
    std::list<std::shared_ptr<DNSRecord>> answer_list, ns_list, ar_list;

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
    int pos = INETDNS::stdstr_has_suffix(q.qname, config->getOrigin());

    // check here if there are direct NS references to this record
    // then this server is not an authority and should instead
    // respond with the NS records..

    std::string trailing_qname = q.qname + std::string(".");
    int has_ns_reference = 0;
    std::string ns_reference_hash;

    // only check this if the query is not the origin

    if (config->getOrigin() != q.qname
            && config->getOrigin() != trailing_qname) {
        ns_reference_hash = q.qname;
        if (INETDNS::stdstr_has_suffix(q.qname, std::string(".")))
            ns_reference_hash = ns_reference_hash + std::string(":");
        else
            ns_reference_hash = ns_reference_hash + std::string(".:");

        ns_reference_hash = ns_reference_hash + std::string(DNS_TYPE_STR_NS)
                + std::string(":") + std::string(DNS_CLASS_STR_IN);

        has_ns_reference = config->hasEntry(ns_reference_hash);

        if (!has_ns_reference) {
            // ok we did not find a reference directly, do a longest suffix match
            // to check if there is a suffix matching
            std::unordered_map<std::string,
                    std::list<std::shared_ptr<zone_entry>>>* zone =
            config->getEntries();
            unsigned int max_len = 0;
            std::string tmp_ref_hash = "";
            for (auto it = (*zone).begin(); it != (*zone).end(); ++it) {
                if (INETDNS::stdstr_has_suffix(ns_reference_hash,
                                it->first)) {
                    if (it->first.length() > max_len) {
                        max_len = it->first.length();
                        tmp_ref_hash = std::string(it->first);
                    }
                }
            }

            if (tmp_ref_hash != "") {
                ns_reference_hash = std::string(tmp_ref_hash);
                has_ns_reference = 1;
            }

        }
    }

    // generate msg name
    std::string msg_name = std::string("dns_response#")
            + std::to_string(response_count++);

    if (pos > 0 && config->getOrigin() != "." && !has_ns_reference) {
        is_authoritative = 1;
    }

    // init class
    switch (q.qclass) {
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
    switch (q.qtype) {
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
    case DNS_TYPE_VALUE_ANY:
        type = DNS_TYPE_STR_ANY;
        break;
    case DNS_TYPE_VALUE_AXFR:
        type = DNS_TYPE_STR_AXFR;
        break;
    }

    // now we can lookup the name in the database
    if (is_authoritative) {
        if (q.qtype == DNS_TYPE_VALUE_ANY) {
            // or the type..
            const char** type_array = INETDNS::getTypeArray();
            for (uint32_t i = 0; i < sizeof(type_array); i++) {
                std::string type_str = std::string(type_array[i]);
                namehash = q.qname;
                if (INETDNS::stdstr_has_suffix(q.qname, std::string(".")))
                    namehash = namehash + std::string(":");
                else
                    namehash = namehash + std::string(".:");

                namehash = namehash + std::string(":") + std::string(__class);

                // we basically just have to append every record that matches
                // the hash to the answer section
                answer_list = appendEntries(namehash, answer_list,
                        INETDNS::getTypeValueForString(type_str),
                        &an_records);
            }

        } else {
            // we have a specific record, so lets look it up in the hash table
            namehash = q.qname;
            if (INETDNS::stdstr_has_suffix(q.qname, std::string(".")))
                namehash = namehash + std::string(":");
            else
                namehash = namehash + std::string(".:");

            namehash = namehash + std::string(type) + std::string(":")
                    + std::string(__class);

            answer_list = appendEntries(namehash, answer_list, q.qtype,
                    &an_records);

            if (an_records > 0) {

                // fill out authority section with NS records
                // if the request was on the ZONE ORIGIN
                // and it was not made for NS records.

                if (q.qtype != DNS_TYPE_VALUE_A
                        && q.qtype != DNS_TYPE_VALUE_AAAA) {
                    ar_list = appendTransitiveEntries(answer_list, ar_list,
                    DNS_TYPE_STR_A, DNS_TYPE_VALUE_A, &ar_records);
                    ar_list = appendTransitiveEntries(answer_list, ar_list,
                    DNS_TYPE_STR_AAAA, DNS_TYPE_VALUE_AAAA, &ar_records);
                }

                // add CNAME if there are links for this label
                if (q.qtype != DNS_TYPE_VALUE_CNAME) {
                    // get NS records
                    cnhash = q.qname;
                    if (INETDNS::stdstr_has_suffix(q.qname,
                            std::string(".")))
                        cnhash = q.qname + std::string(":");
                    else
                        cnhash = q.qname + std::string(".:");

                    cnhash = cnhash + std::string(DNS_TYPE_STR_CNAME)
                            + std::string(":") + std::string(__class);

                    answer_list = appendEntries(cnhash, answer_list,
                    DNS_TYPE_VALUE_CNAME, &an_records);

                    // now we don't add the QTYPE record to additional, but to the answer section
                    // iterate through the CNAME records, add the QTYPE records accordingly....
                    for (auto it = answer_list.begin(); it != answer_list.end();
                            ++it) {
                        std::shared_ptr<DNSRecord> t_r = *it;
                        // use the data string to create a hash and find the qtype record
                        std::string namecpy = std::string(t_r->strdata);
                        cnhash = namecpy + std::string(".")
                                + config->getOrigin() + std::string(":")
                                + std::string(type) + std::string(":")
                                + std::string(__class);

                        // get entries for type using this hash
                        answer_list = appendEntries(cnhash, answer_list,
                                q.qtype, &an_records);
                    }
                }
            } else {
                // add CNAME if there are links for this label
                if (q.qtype != DNS_TYPE_VALUE_CNAME) {
                    // get NS records
                    cnhash = q.qname;
                    if (INETDNS::stdstr_has_suffix(q.qname,
                            std::string(".")))
                        cnhash = q.qname + std::string(":");
                    else
                        cnhash = q.qname + std::string(".:");

                    cnhash = cnhash + std::string(DNS_TYPE_STR_CNAME)
                            + std::string(":") + std::string(__class);

                    answer_list = appendEntries(cnhash, answer_list,
                    DNS_TYPE_VALUE_CNAME, &an_records);

                    for (auto it = answer_list.begin(); it != answer_list.end();
                            ++it) {
                        std::shared_ptr<DNSRecord> t_r = *it;
                        // use the data string to create a hash and find the qtype record
                        std::string namecpy = std::string(t_r->strdata);
                        cnhash = namecpy + std::string(".")
                                + config->getOrigin() + std::string(":")
                                + std::string(type) + std::string(":")
                                + std::string(__class);

                        // get entries for type using this hash
                        answer_list = appendEntries(cnhash, answer_list,
                                q.qtype, &an_records);
                    }
                }
            }

        }

        if (an_records == 0) {   // no entry found, although authoritative
                                 // append SOA
            response = INETDNS::createResponse(msg_name, 1, 0, 0, 0, id,
                    opcode, 1, rd, ra, 3);
        } else {
            // append authority
            ns_list = appendAuthority(ns_list, &ns_records);
            if (ns_records > 0) {
                ar_list = appendAdditionals(ns_list, ar_list, &ar_records);
            }

            response = INETDNS::createResponse(msg_name, 1, an_records,
                    ns_records, ar_records, id, opcode, 1, rd, ra, 0);
        }

        INETDNS::appendQuestion(response,
                INETDNS::copyDnsQuestion(&q), 0);
    } else {
        // we're not authoritative, but maybe we have an entry that points
        // to an NS that is authoritative for a suffix of the query

        bool found_entry = false;

        // tokenize the question label. check if theres an entry for the last suffix, i.e. last token
        std::vector<std::string> tokens =
                cStringTokenizer(q.qname.c_str(), ".").asVector();
        // check last token and create hash using NS
        std::string reference_hash = tokens[tokens.size() - 1]
                + std::string(".:") + std::string(DNS_TYPE_STR_NS)
                + std::string(":") + std::string(__class);

        if (has_ns_reference) { // see if we know a nameserver on the prefix
            found_entry = true;
            ns_list = appendEntries(ns_reference_hash, ns_list,
            DNS_TYPE_VALUE_NS, &ns_records);

            ar_list = appendTransitiveEntries(ns_list, ar_list, DNS_TYPE_STR_A,
            DNS_TYPE_VALUE_A, &ar_records);
            ar_list = appendTransitiveEntries(ns_list, ar_list,
            DNS_TYPE_STR_AAAA, DNS_TYPE_VALUE_AAAA, &ar_records);

            // response with with no AA set
            response = INETDNS::createResponse(msg_name, 1, an_records,
                    ns_records, ar_records, id, opcode, 0, rd, ra, 0);

            // set question
            INETDNS::appendQuestion(response,
                    INETDNS::copyDnsQuestion(&q), 0);

        } else if (config->hasEntry(reference_hash)) {
            found_entry = true;
            ns_list = appendEntries(reference_hash, ns_list, DNS_TYPE_VALUE_NS,
                    &ns_records);

            if (ns_records != 0) {

                ar_list = appendTransitiveEntries(ns_list, ar_list,
                DNS_TYPE_STR_A, DNS_TYPE_VALUE_A, &ar_records);
                ar_list = appendTransitiveEntries(ns_list, ar_list,
                DNS_TYPE_STR_AAAA, DNS_TYPE_VALUE_AAAA, &ar_records);

                // response with with no AA set
                response = INETDNS::createResponse(msg_name, 1,
                        an_records, ns_records, ar_records, id, opcode, 0, rd,
                        ra, 0);
            }
        }

        if (!found_entry) {

            if (recursion_available && rootServers.size() > 0) {
                if (rd) {
                    // assign an id for the query cache
                    int id = DNSServerBase::getIdAndInc();
                    DNSServerBase::store_in_query_cache(id, query);
                    msg_name = std::string("dns_query#") + std::to_string(id)
                            + std::string("--recursive");

                    // do the initial query towards a root server
                    // pick at random
                    int p = intrand(rootServers.size());
                    DNSPacket *root_q = INETDNS::createQuery(msg_name,
                            query->questions[0].qname, DNS_CLASS_IN,
                            query->questions[0].qtype, id, 1);

                    DNSServerBase::sendResponse(root_q, rootServers[p]);

                    return NULL; // so it is known that recursive resolving has been initiated

                } else {
                    // response with not found err
                    response = INETDNS::createResponse(msg_name, 1,
                            an_records, ns_records, ar_records, id, opcode, 0,
                            rd, ra, 0);
                }

                // set question
                INETDNS::appendQuestion(response,
                        INETDNS::copyDnsQuestion(&q), 0);
            } else {
                //TODO; Iterative answer.
                response = DNSServerBase::unsupportedOperation(query);
                return response;
            }
        }
    }

    // append an, ns, ar to response
    int index = 0;
    if (an_records > 0) {
        for (auto it = answer_list.begin(); it != answer_list.end(); ++it) {
            INETDNS::appendAnswer(response, *it, index++);
        }
    }
    if (ns_records > 0) {
        index = 0;
        for (auto it = ns_list.begin(); it != ns_list.end(); ++it) {
            INETDNS::appendAuthority(response, *it, index++);
        }
    }
    if (ar_records > 0) {
        index = 0;
        for (auto it = ar_list.begin(); it != ar_list.end(); ++it) {
            INETDNS::appendAdditional(response, *it, index++);
        }
    }
    if (an_records == 0 && ns_records == 0 && ar_records == 0) {
        // just append the SOA entry.
    }

    return response;

}

std::list<std::shared_ptr<DNSRecord>> DNSAuthServer::appendAuthority(
        std::list<std::shared_ptr<DNSRecord>> ns_list, int *ns_records) {
    std::string nshash = config->getOrigin() + std::string(":")
            + std::string(DNS_TYPE_STR_NS) + std::string(":")
            + std::string(DNS_CLASS_STR_IN);
    ns_list = appendEntries(nshash, ns_list, DNS_TYPE_VALUE_NS, ns_records);
    return ns_list;
}

std::list<std::shared_ptr<DNSRecord>> DNSAuthServer::appendAdditionals(
        std::list<std::shared_ptr<DNSRecord>> ns_list,
        std::list<std::shared_ptr<DNSRecord>> ar_list, int *ar_records) {
    ar_list = appendTransitiveEntries(ns_list, ar_list,
    DNS_TYPE_STR_A, DNS_TYPE_VALUE_A, ar_records);
    ar_list = appendTransitiveEntries(ns_list, ar_list,
    DNS_TYPE_STR_AAAA, DNS_TYPE_VALUE_AAAA, ar_records);

    return ar_list;
}

std::list<std::shared_ptr<DNSRecord>> DNSAuthServer::appendEntries(
        std::string hash, std::list<std::shared_ptr<DNSRecord>> dstlist,
        int type, int *num_records) {
    std::list<std::shared_ptr<zone_entry>> entries = config->getEntry(hash);
    std::shared_ptr<INETDNS::DNSRecord> rr;

    for (auto entry : entries) {
        rr = std::shared_ptr < INETDNS::DNSRecord > (new DNSRecord());
        rr->rdata = NULL;
        rr->strdata = std::string(entry->data);

        if (INETDNS::stdstr_has_suffix(entry->domain,
                config->getOrigin())) {
            rr->rname = std::string(entry->domain);
        } else {
            rr->rname = std::string(entry->domain) + std::string(".")
                    + std::string(config->getOrigin());
        }

        rr->rclass = (short) DNS_CLASS_IN;
        rr->rtype = (short) type;
        rr->rdlength = entry->data.length();
        rr->ttl = config->getTTL();

        dstlist.push_back(rr);
        (*num_records)++;
    }
    return dstlist;
}

std::list<std::shared_ptr<DNSRecord>> DNSAuthServer::appendTransitiveEntries(
        std::list<std::shared_ptr<DNSRecord>> srclist,
        std::list<std::shared_ptr<DNSRecord>> dstlist, const char* DNS_TYPE_STR,
        int DNS_TYPE_VALUE, int *ar_records) {
    std::string hash;

    // iterate through the source list
    for (auto it = srclist.begin(); it != srclist.end(); ++it) {
        // get the zone entry
        auto record = *it;

        // calculate hash from domain + type + class
        // first ar hash is for A records..
        if (record->rtype == DNS_TYPE_VALUE_SRV) {
            std::shared_ptr<INETDNS::SRVData> srv =
                    std::static_pointer_cast < INETDNS::SRVData
                            > (record->rdata);
            hash = srv->target + std::string(":") + std::string(DNS_TYPE_STR)
                    + std::string(":") + std::string(DNS_CLASS_STR_IN);
        } else {
            hash = record->strdata + std::string(":")
                    + std::string(DNS_TYPE_STR) + std::string(":")
                    + std::string(DNS_CLASS_STR_IN);
        }

        std::list<std::shared_ptr<zone_entry>> transitive_entries =
                config->getEntry(hash);
        std::shared_ptr<INETDNS::DNSRecord> dns_record;

        // go through
        for (auto it_2 = transitive_entries.begin();
                it_2 != transitive_entries.end(); ++it_2) {
            auto entry = *it_2;
            dns_record = std::shared_ptr < INETDNS::DNSRecord
                    > (new DNSRecord());
            dns_record->rdata = NULL;
            dns_record->strdata = std::string(entry->data);

            if (INETDNS::stdstr_has_suffix(entry->domain,
                    config->getOrigin())) {
                dns_record->rname = std::string(entry->domain);
            } else {
                dns_record->rname = entry->domain + std::string(".")
                        + config->getOrigin();
            }

            dns_record->rclass = (short) DNS_CLASS_IN;
            dns_record->rtype = (short) DNS_TYPE_VALUE;
            dns_record->rdlength = entry->data.length();
            dns_record->ttl = config->getTTL();

            dstlist.push_back(dns_record);
            (*ar_records)++;
        }
    }

    return dstlist;
}
