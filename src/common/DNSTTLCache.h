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

namespace INETDNS {

/**
 * @brief Struct wrapping @ref DNSRecord with timing information.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct DNSTimeRecord {
    /**
     * @brief The record for which time information needs to be stored.
     */
    std::shared_ptr<DNSRecord> record;

    /**
     * @brief A helper string containing the hash.
     */
    std::string hash;

    /**
     * @brief The receiving time of this record.
     */
    simtime_t rcv_time;

    /**
     * @brief The time the record expires.
     *
     * It is calculated from the receive time added with the time to live
     * of the record.
     */
    simtime_t expiry;

    DNSTimeRecord() :
            record(NULL), hash(""), rcv_time(0), expiry(0) {
    }
    ;

} dns_time_record;

/**
 * @brief This class is used for comparing @ref DNSTimeRecord
 *
 * and provided to standard library containers that need comparators
 * in order to sort their entries.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class DNSTimeRecordComparator {
public:
    DNSTimeRecordComparator() {

    }
    virtual ~DNSTimeRecordComparator() {

    }

    bool operator()(std::shared_ptr<INETDNS::DNSTimeRecord> t1,
            std::shared_ptr<INETDNS::DNSTimeRecord> t2) {
        // t1 < t2,
        // meaning t1s time is up before t2s
        return t1->expiry < t2->expiry;
    }
};

/**
 * @brief DNSTTLCache is a TTL based cached.
 *
 * This means that once a record has outlived it's time to live,
 * it is removed from the cache. If eviction is necessary due to
 * a full cache, oldest entries are removed first, until 10%
 * of the lists of records are removed.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class DNSTTLCache: public DNSCache {
public:
    DNSTTLCache();
    virtual ~DNSTTLCache();

    int put_into_cache(std::shared_ptr<DNSRecord> record);
    std::list<std::shared_ptr<DNSRecord>> get_from_cache(std::string hash);
    int is_in_cache(std::string hash);
    std::list<std::shared_ptr<DNSRecord>> remove_from_cache(std::string hash);
    std::shared_ptr<DNSRecord> remove_from_cache(std::string hash, std::shared_ptr<DNSRecord> r);
    std::list<std::shared_ptr<DNSRecord>> evict();
    std::list<std::string> get_matching_hashes(std::string hash);

    /**
     * @brief Check whether the record has half its ttl reached.
     *
     * @param r The @ref DNSRecord for which the ttl needs to be checked.
     *
     * @return 1 if half the ttl has passed, 0 otherwise.
     */
    int halfTTL(std::shared_ptr<DNSRecord> r);

    /**
     * @brief cleans records from the cache, which ttls expired
     * @return return removed records
     */
    std::list<std::shared_ptr<DNSRecord>> cleanup();

    /**
     * @brief Retrieve the cache table used for caching Records
     *
     * @return an unordered map containing hash/list of @ref DNSTimeRecord pairs.
     */
    std::unordered_map<std::string, std::list<std::shared_ptr<DNSTimeRecord>>> get_cache_table() {
        return cache;
    }

protected:
    /**
     * @brief Map from strings to lists of @ref DNSTimeRecord
     *
     * used as the cache for dns records.
     */
    std::unordered_map<std::string, std::list<std::shared_ptr<DNSTimeRecord>>> cache;

    /**
     * @brief Ordered set containing the @ref DNSTimeRecord in the cache.
     *
     * Used to quickly find and store @ref DNSTimeRecord by their time
     * of expiry.
     */
    std::set<std::shared_ptr<INETDNS::DNSTimeRecord>,
            INETDNS::DNSTimeRecordComparator> dnsRecordPriorityCache;

    /**
     * @brief Remove a given @ref DNSTimeRecord from the cache.
     *
     * @param tr @ref DNSTimeRecord that needs to be removed.
     */
    void remove_time_record(std::shared_ptr<DNSTimeRecord> tr);
};

} /* namespace ODnsExtension */

#endif /* DNSTTLCACHE_H_ */
