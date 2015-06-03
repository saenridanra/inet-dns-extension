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

#ifndef DNSSIMPLECACHE_H_
#define DNSSIMPLECACHE_H_

#include <math.h>
#include "DNSCache.h"
#include <algorithm>
#include "utils/Utils.h"

namespace INETDNS {

/**
 * @brief DNSSimpleCache is a simple cache implementation
 * with random eviction. Once the maximum amount of records
 * is reached, 10% of the lists of records are randomly
 * evicted.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class DNSSimpleCache : public DNSCache {

public:
    DNSSimpleCache();
    virtual ~DNSSimpleCache();

    int put_into_cache(std::shared_ptr<DNSRecord> record);
    std::list<std::shared_ptr<DNSRecord>> get_from_cache(std::string hash);
    int is_in_cache(std::string hash);
    std::list<std::shared_ptr<DNSRecord>> remove_from_cache(std::string hash);
    std::shared_ptr<DNSRecord> remove_from_cache(std::string hash, std::shared_ptr<DNSRecord> r);
    std::list<std::shared_ptr<DNSRecord>> evict();
    std::list<std::string> get_matching_hashes(std::string hash);

protected:
    /**
     * @brief Map from strings to lists of @ref DNSRecord
     *
     * used as the cache for dns records.
     */
    std::unordered_map<std::string, std::list<std::shared_ptr<DNSRecord>>> cache;
};

} /* namespace ODnsExtension */

#endif /* DNSSIMPLECACHE_H_ */
