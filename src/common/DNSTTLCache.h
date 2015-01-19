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

#include <math.h>
#include "DNSCache.h"
#include <omnetpp.h>

namespace ODnsExtension {

typedef struct DNSTimeRecord{
   DNSRecord*  record;
   char* hash;
   simtime_t rcv_time;
   simtime_t expiry;
} dns_time_record;

class DNSTimeRecordComparator{
    public:
        DNSTimeRecordComparator();
        virtual ~DNSTimeRecordComparator();

        bool operator() (ODnsExtension::DNSTimeRecord* t1, ODnsExtension::DNSTimeRecord* t2){
            // t1 < t2,
            // meaning t1s time is up before t2s

            return t1->expiry < t2->expiry;
        }
};

class DNSTTLCache: public DNSCache
{
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
    int put_into_cache(DNSRecord* record);

    /**
     * @brief get_from_cache
     * @params
     *      hash - the hash value for the record, note it has the form <label:type:class>
     * @return
     *      the desired dns records, returns null if there is no such record for the given hash.
     */
    GList* get_from_cache(char* hash);

    /**
     * @brief is_in_cache
     * @params
     *      hash - the hash value for the record, note it has the form <label:type:class>
     * @return
     *      1 if there is an entry
     *      0 otherwise
     */
    int is_in_cache(char* hash);

    /**
     * @brief remove_from_cache
     * Removes the record from the cache and returns it.
     *
     * @params
     *      hash - the hash value for the record, note it has the form <label:type:class>
     * @return
     *      returns the removed records.
     */
    GList* remove_from_cache(char* hash);

    /**
     * @brief cleanup
     *  cleans records from the cache, which ttl expired
     */

    void cleanup();

    /**
     * @brief evict
     * Removes a random record from the cache.
     *
     * @return
     *      the evicted dns records.
     */
    GList* evict();

    protected:
        GHashTable* cache;
        std::set<ODnsExtension::DNSTimeRecord*, ODnsExtension::DNSTimeRecordComparator> dnsRecordPriorityCache;
};

} /* namespace ODnsExtension */

#endif /* DNSTTLCACHE_H_ */
