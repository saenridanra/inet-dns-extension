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
#include "../utils/DNSTools.h"
#include "glib.h"
#include "glib/gprintf.h"

namespace ODnsExtension {


/**
 * @brief DNSCache is an interface providing methods
 * to implement DNSCaches for records.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 */
class DNSCache {
public:
    DNSCache();
    virtual ~DNSCache();
    virtual int put_into_cache(DNSRecord* record) = 0;
    virtual GList* get_from_cache(char* hash) = 0;
    virtual GList* remove_from_cache(char* hash) = 0;
    virtual int is_in_cache(char* hash) = 0;
    virtual GList* evict() = 0;
    virtual GList* get_matching_hashes(char* hash) = 0;

    void setMaxRecords(int _max_records)
    {
      max_records = _max_records;
    }

    int getMaxRecords(){
        return max_records;
    }

    void setCacheSize(int cs)
    {
        current_cache_size = cs;
    }

    int getCacheSize(){
        return current_cache_size;
    }

protected:
    int max_records = 100; // default
    int current_cache_size;

};

} /* namespace ODnsExtension */

#endif /* DNSCACHE_H_ */
