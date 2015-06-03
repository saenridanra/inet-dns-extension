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

#ifndef DNSCACHE_H_
#define DNSCACHE_H_

#include "DNS.h"
#include "DNSTools.h"
#include <list>
#include <unordered_map>
#include <memory>

namespace INETDNS {

/**
 * @brief @ref DNSCache is an interface providing methods
 * to implement DNSCaches for records.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class DNSCache {
public:
    DNSCache();
    virtual ~DNSCache();

    /**
     * @brief Put a @ref DNSRecord into the cache.
     * @param r @ref DNSRecord that is put into the cache.
     *
     * @return 1 if successful, 0 otherwise.
     */
    virtual int put_into_cache(std::shared_ptr<DNSRecord> r) = 0;

    /**
     * @brief Retrieve a list of @ref DNSRecord from the cache.
     * @param hash String valued hash for the given record.
     * @return list of @ref DNSRecord
     */
    virtual std::list<std::shared_ptr<DNSRecord>> get_from_cache(std::string hash) = 0;

    /**
     * @brief Remove a list of @ref DNSRecord from the cache.
     * @param hash String valued hash for the given record.
     * @return list of removed @ref DNSRecord
     */
    virtual std::list<std::shared_ptr<DNSRecord>> remove_from_cache(std::string hash) = 0;

    /**
     * @brief Remove a specific @ref DNSRecord from the cache.
     * @param hash String valued hash for the given record.
     * @return removed @ref DNSRecord
     */
    virtual std::shared_ptr<INETDNS::DNSRecord> remove_from_cache(std::string hash, std::shared_ptr<INETDNS::DNSRecord> r) = 0;

    /**
     * @brief Check whether records exist for a given hash.
     * @param hash String valued hash for the given record.
     * @return 1 if there exists a @ref DNSRecord list, 0 otherwise
     */
    virtual int is_in_cache(std::string hash) = 0;

    /**
     * @brief Remove a list of @ref DNSRecord from the cache.
     *
     * The method of removing a certain list is up to the implementor
     * of the cache.
     * @return removed list of @ref DNSRecord
     */
    virtual std::list<std::shared_ptr<DNSRecord>> evict() = 0;

    /**
     * @brief Retrieve a list of hashes
     *
     * for a given hash, based on suffix matching to the hash.
     * @param hash String valued hash for which matches are desired.
     * @return List of strings containing matching hashes.
     */
    virtual std::list<std::string> get_matching_hashes(std::string hash) = 0;

    /**
     * @brief Set the max amount of records.
     *
     * If the maximum is to be exceeded, eviction has
     * to be performed.
     *
     * @param _max_records The amount of records, that can be stored within the cache.
     */
    void setMaxRecords(int _max_records)
    {
      max_records = _max_records;
    }

    /**
     * @brief Get the max amount of records.
     *
     * @return The amount of records, that can be stored within the cache.
     */
    int getMaxRecords(){
        return max_records;
    }

    /**
     * @brief Set the current cache table size
     *
     * @param cs Current cache table size
     */
    void setCacheSize(int cs)
    {
        current_cache_size = cs;
    }

    /**
     * @brief Get the current cache table size
     *
     * @return Current cache table size
     */
    int getCacheSize(){
        return current_cache_size;
    }

protected:
    /**
     * @brief Member variable for the maximum amount of records.
     */
    int max_records = 100;
    /**
     * @brief Member variable for the current cache size.
     */
    int current_cache_size;

};

} /* namespace ODnsExtension */

#endif /* DNSCACHE_H_ */
