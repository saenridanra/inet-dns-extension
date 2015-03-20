/* Copyright (c) 2014 Andreas Rain

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
#include <DNSTTLCache.h>

namespace ODnsExtension {

DNSTTLCache::DNSTTLCache() {
    // we don't need to destroy  the record in the hashfunc, since the evction
    // returns the record. If necessary it will be deleted
    setCacheSize(0);
}

DNSTTLCache::~DNSTTLCache() {
    // Destroy the cache
    while(g_hash_table_size(cache) > 0){
        // evict and free the record.
        std::list<DNSRecord*> list = evict();
        for(auto it : list){
            freeDnsRecord(*it);
        }
        list.clear();
        setCacheSize(getCacheSize()-1);
    }
}

int DNSTTLCache::put_into_cache(DNSRecord* record){
    // calculate the hash, check if it's already in the cache.

    if(!record->rdata){
        throw cRuntimeError("Retrieved invalid record to put into cache");
    }

    std::string type = std::string(getTypeStringForValue(record->rtype));
    std::string _class = std::string(getClassStringForValue(record->rclass));

    // create hash:
    std::string hash = record->rname + std::string(":") + type + std::string(":") + _class;

    // check if it is in the cache
    if(!is_in_cache(hash)){
        if(DNSCache::getCacheSize() > DNSCache::getMaxRecords()){
            evict();
        }

        std::list<DNSTimeRecord*> list = NULL;
        DNSTimeRecord* time_record = new DNSTimeRecord();

        time_record->record = record;
        time_record->hash = hash;
        time_record->rcv_time = simTime();

        std::string stime = std::to_string(record->ttl) + std::string("s");
        simtime_t tv = simTime() + STR_SIMTIME(stime.c_str());
        time_record->expiry = time_record->rcv_time + tv;

        //g_printf("DEBUG MSG: New hash entering CACHE --- [%s], for record->rname=%s\n", hash, record->rname);
        list.push_back(time_record);
        cache[hash] = list;
        dnsRecordPriorityCache.insert(time_record);
        setCacheSize(getCacheSize()+1);
    }
    else{
        // check if the data is still the same
        std::list<DNSTimeRecord*> from_cache = cache[hash];

        int is_already_in_cache = 0;
        for(auto it : from_cache){
            DNSTimeRecord* record_from_cache = *it;

            if(ODnsExtension::recordDataEqual(record->rdata, record_from_cache->record->rdata)){
                is_already_in_cache = 1;
                // update expiry by new data
                break;
            }
        }

        if(!is_already_in_cache){
            // create a new time record
            DNSTimeRecord* time_record = new DNSTimeRecord();
            time_record->record = record;
            time_record->hash = hash;
            time_record->rcv_time = simTime();

            std::string stime = std::to_string(record->ttl) + std::string("s");
            simtime_t tv = simTime() + STR_SIMTIME(stime.c_str());
            time_record->expiry = time_record->rcv_time + tv;

            // replace the entry in the database
            from_cache = cache[hash];
            from_cache.push_back(time_record);
            cache[hash] = from_cache;

            dnsRecordPriorityCache.insert(time_record);
        }
    }

    return 1;

}

std::list<DNSRecord*> DNSTTLCache::get_from_cache(std::string hash){
    std::list<DNSTimeRecord*> from_cache = cache[hash];
    // create a list containing the DNSRecords
    std::list<DNSRecord*> record_list;
    for(auto it : from_cache){
        record_list.push_back((*it)->record);
    }

    return record_list;

}

int DNSTTLCache::is_in_cache(std::string hash){
    return cache.find(hash) != cache.end();
}

int DNSTTLCache::halfTTL(DNSRecord* r){
    // get the time record list for the hash from the cache
    std::string type = std::string(getTypeStringForValue(r->rtype));
    std::string _class = std::string(getClassStringForValue(r->rclass));

    // create hash:
    std::string hash = r->rname + std::string(":") + type + std::string(":") + _class;
    std::list<DNSTimeRecord*> tr_list = cache[hash];
    for(auto kv : tr_list){
        DNSTimeRecord* tr = kv.second;
        DNSRecord* record = tr->record;

        if(ODnsExtension::recordDataEqual(r, record)){
            std::string stime = std::to_string(r->ttl) + std::string("s");
            simtime_t ttl_to_sim = STR_SIMTIME(stime.c_str());
            simtime_t curr = simTime();
            return (tr->expiry - curr).inUnit(-3) < (ttl_to_sim / 2).inUnit(-3);
        }
    }

    return 0;
}

std::list<DNSRecord*> DNSTTLCache::cleanup(){
    std::set<ODnsExtension::DNSTimeRecord*>::iterator iterator;
    std::list<DNSRecord*> returnlist = NULL;
    for(auto iterator : dnsRecordPriorityCache){
        DNSTimeRecord* r = *iterator;
        if(r->expiry < simTime()){
            // remove from caches
            dnsRecordPriorityCache.erase(iterator);
            DNSRecord* removed_record = remove_from_cache(r->hash, r->record);
            delete r;
            returnlist.push_back(removed_record);
        }
        else{
            break; // we're finished cleaning up.
        }
    }

    return returnlist;
}

std::list<DNSRecord*> DNSTTLCache::remove_from_cache(std::string hash){
    std::list<DNSTimeRecord*> from_cache = cache[hash];
    std::list<DNSRecord*> return_list;
    if(from_cache.size() > 0){
        cache.erase(hash);
        setCacheSize(getCacheSize()-1);

        // remove all time records from the priority queue ..
        for(auto it : from_cache){
            dnsRecordPriorityCache.erase(it++);
            return_list.push_back((*it)->record);
            delete *it;
        }

        return return_list;
    }

    return NULL;
}

DNSRecord* DNSTTLCache::remove_from_cache(std::string hash, DNSRecord* r){
    std::list<DNSTimeRecord*> from_cache = cache[hash];

    for(auto it : from_cache){
        DNSTimeRecord* tr = *it;

        if(ODnsExtension::recordDataEqual(tr->record, r)){
            // we have the record
            from_cache.erase(tr);
            // replace the list in the table
            cache[hash] = from_cache;
            // free the time record, return the record
            DNSRecord* return_record = tr->record;
            remove_time_record(tr);
            delete tr;
            return return_record;
        }
    }

    // this means we did not find the record, return NULL
    return NULL;
}



void DNSTTLCache::remove_time_record(DNSTimeRecord* tr)
{
    std::set<ODnsExtension::DNSTimeRecord*, ODnsExtension::DNSTimeRecordComparator>::iterator it;

    for(auto it : dnsRecordPriorityCache){
        if(*it == tr){
            dnsRecordPriorityCache.erase(it++);
            continue;
        }
    }
}

std::list<DNSRecord*> DNSTTLCache::evict(){
    if(getCacheSize() == 0){
        return NULL;
    }

    // evict top element...
    ODnsExtension::DNSTimeRecord* top = *dnsRecordPriorityCache.begin();

    return remove_from_cache(top->hash);
}

std::list<std::string> DNSTTLCache::get_matching_hashes(std::string hash){
    std::list<std::string> hashes;
    for(auto kv : cache){
        if(ODnsExtension::stdstr_has_suffix(hash, kv.first)){
            // we have a match, append it to the return list
            std:string hash_cpy = std::string(kv.first);
            hashes.push_back(hash_cpy);
        }
    }

    return hashes;
}

}
