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

#include <DNSSimpleCache.h>

namespace INETDNS {

DNSSimpleCache::DNSSimpleCache() {
    // we don't need to destroy  the record in the hashfunc, since the evction
    // returns the record. If necessary it will be deleted
    setCacheSize(0);
}

DNSSimpleCache::~DNSSimpleCache() {
    // Destroy the cache
    while(getCacheSize() > 0){
        // evict and free the record.
        std::list<std::shared_ptr<DNSRecord>> list = evict();
        setCacheSize(getCacheSize()-1);
        // clear list elements
        list.clear();

    }
}

int DNSSimpleCache::put_into_cache(std::shared_ptr<DNSRecord> record){
    // calculate the hash, check if it's already in the cache.

    if(!record->rdata && record->strdata == ""){
        throw cRuntimeError("Retrieved invalid record to put into cache");
    }

    std::string type = std::string(getTypeStringForValue(record->rtype));
    std::string _class = std::string(getClassStringForValue(record->rclass));

    // create hash:
    std::string hash = record->rname + std::string(":") + type + std::string(":") + _class;

    // check if it is in the cache
    if(!is_in_cache(hash)){
        if(DNSCache::getCacheSize() > DNSCache::getMaxRecords()){
            // evict and free 10% of the records.
            for(int i=0; i < floor(DNSCache::getMaxRecords()/10); i++){
                std::list<std::shared_ptr<DNSRecord>> list = (std::list<std::shared_ptr<DNSRecord>>) evict();
                // clear list elements
                list.clear();

                setCacheSize(getCacheSize()-1);
            }
        }

        std::list<std::shared_ptr<DNSRecord>> list;
        list.push_back(record);

        cache[hash] = list;
        setCacheSize(getCacheSize()+1);
    }
    else{
        // check if the data is still the same
        std::list<std::shared_ptr<DNSRecord>> from_cache = cache[hash];

        int is_already_in_cache = 0;
        for(auto it = from_cache.begin(); it != from_cache.end(); ++it){
            std::shared_ptr<DNSRecord> record_from_cache = *it;

            if(INETDNS::recordDataEqual(record_from_cache, record)){
                is_already_in_cache = 1;
                break;
            }
        }

        if(!is_already_in_cache){
            // append the record
            from_cache = cache[hash];
            from_cache.push_back(record);
            cache[hash] = from_cache;
        }
    }

    return 1;


}

std::list<std::shared_ptr<DNSRecord>> DNSSimpleCache::get_from_cache(std::string hash){
    if(!is_in_cache(hash)) return std::list<std::shared_ptr<DNSRecord>>();
    return cache[hash];
}

int DNSSimpleCache::is_in_cache(std::string hash){
    return cache.find(hash) != cache.end();
}

std::list<std::shared_ptr<DNSRecord>> DNSSimpleCache::remove_from_cache(std::string hash){
    if(!is_in_cache(hash)) return std::list<std::shared_ptr<DNSRecord>>();
    std::list<std::shared_ptr<DNSRecord>> from_cache = cache[hash];
    cache.erase(hash);
    return from_cache;
}

std::list<std::shared_ptr<DNSRecord>> DNSSimpleCache::evict(){
    if(getCacheSize() == 0){
        return std::list<std::shared_ptr<DNSRecord>>();
    }
    std::string eviction_key;

    int p = intrand(getCacheSize());
    int c = 0;
    for(auto kv : cache) {
        if(c == p){
            eviction_key = kv.first;
            break;
        }
    }

    return remove_from_cache(eviction_key);
}

std::shared_ptr<DNSRecord> DNSSimpleCache::remove_from_cache(std::string hash, std::shared_ptr<DNSRecord> r){
    if(!is_in_cache(hash)) return NULL;
    std::list<std::shared_ptr<DNSRecord>> from_cache = cache[hash];
    from_cache.erase(std::find(from_cache.begin(), from_cache.end(), r));
    cache[hash] = from_cache;
    return r;
}

std::list<std::string> DNSSimpleCache::get_matching_hashes(std::string hash){
    std::list<std::string> hashes;
    for(auto kv : cache){
        if(INETDNS::stdstr_has_suffix(hash, kv.first)){
            // we have a match, append it to the return list
            std::string hash_cpy = std::string(kv.first);
            hashes.push_back(hash_cpy);
        }
    }

    return hashes;

}


} /* namespace ODnsExtension */
