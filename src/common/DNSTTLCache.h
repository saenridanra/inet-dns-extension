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

#ifndef DNSTTLCACHE_H_
#define DNSTTLCACHE_H_

#include <omnetpp.h>
#include <math.h>
#include "DNSCache.h"
#include "utils/Utils.h"

#include <string>

namespace ODnsExtension {

typedef struct DNSTimeRecord {
    std::shared_ptr<DNSRecord> record;
    std::string hash;
    simtime_t rcv_time;
    simtime_t expiry;

    DNSTimeRecord() :
            record(NULL), hash(NULL), rcv_time(0), expiry(0) {
    }
    ;

} dns_time_record;

class DNSTimeRecordComparator {
public:
    DNSTimeRecordComparator() {

    }
    virtual ~DNSTimeRecordComparator() {

    }

    bool operator()(std::shared_ptr<ODnsExtension::DNSTimeRecord> t1,
            std::shared_ptr<ODnsExtension::DNSTimeRecord> t2) {
        // t1 < t2,
        // meaning t1s time is up before t2s

        return t1->expiry < t2->expiry;
    }
};

class DNSTTLCache: public DNSCache {
public:
    DNSTTLCache();
    virtual ~DNSTTLCache();/**

     * @brief put_into_cache
     * @params
     *      record - the DNSRecord* that has to be stored in the cache
     * @return
     *      1 if the value was stored
     *      0 if the value was not stored
     */
    int put_into_cache(std::shared_ptr<DNSRecord> record);

    /**
     * @brief get_from_cache
     * @params
     *      hash - the hash value for the record, note it has the form <label:type:class>
     * @return
     *      the desired dns records, returns null if there is no such record for the given hash.
     */
    std::list<std::shared_ptr<DNSRecord>> get_from_cache(std::string hash);

    /**
     * @brief is_in_cache
     * @params
     *      hash - the hash value for the record, note it has the form <label:type:class>
     * @return
     *      1 if there is an entry
     *      0 otherwise
     */
    int is_in_cache(std::string hash);

    /**
     * @brief halfTTL
     *  returns whether the record has outlived half its lifetime.
     */

    int halfTTL(std::shared_ptr<DNSRecord> r);

    /**
     * @brief remove_from_cache
     * Removes the record from the cache and returns it.
     *
     * @params
     *      hash - the hash value for the record, note it has the form <label:type:class>
     * @return
     *      returns the removed records.
     */
    std::list<std::shared_ptr<DNSRecord>> remove_from_cache(std::string hash);

    /**
     * @brief remove_from_cache
     * Removes the record from the cache and returns it.
     *
     * @params
     *      hash - the hash value for the record, note it has the form <label:type:class>
     *      r    - a specific record that has to be removed from the list for this hash
     * @return
     *      returns the removed record.
     */
    std::shared_ptr<DNSRecord> remove_from_cache(std::string hash, std::shared_ptr<DNSRecord> r);

    /**
     * @brief cleanup
     *  cleans records from the cache, which ttl expired
     *
     * @return
     *      return removed records
     */

    std::list<std::shared_ptr<DNSRecord>> cleanup();

    /**
     * @brief evict
     * Removes a random record from the cache.
     *
     * @return
     *      the evicted dns records.
     */
    std::list<std::shared_ptr<DNSRecord>> evict();

    /**
     * @brief get_matching_hashes
     * Perform a cache walk on the hashes and check if
     * we find substrings of @param hash
     *
     * @param
     *  hash - hash that we want to match for
     *
     * @return
     *      list of matching hashes in the cache
     *
     */
    std::list<std::string> get_matching_hashes(std::string hash);

    /**
     * @brief
     * Retrieve the cache table used for caching Records
     *
     * @return
     *      an unordered map containing hash/record pairs.
     */
    std::unordered_map<std::string, std::list<std::shared_ptr<DNSTimeRecord>>> get_cache_table() {
        return cache;
    }

protected:
    std::unordered_map<std::string, std::list<std::shared_ptr<DNSTimeRecord>>> cache;
    std::set<std::shared_ptr<ODnsExtension::DNSTimeRecord>,
            ODnsExtension::DNSTimeRecordComparator> dnsRecordPriorityCache;

    void remove_time_record(std::shared_ptr<DNSTimeRecord> tr);
};

} /* namespace ODnsExtension */

#endif /* DNSTTLCACHE_H_ */
