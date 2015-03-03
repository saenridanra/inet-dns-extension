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
    cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    setCacheSize(0);
}

DNSTTLCache::~DNSTTLCache() {
    // Destroy the cache
    while(g_hash_table_size(cache) > 0){
        // evict and free the record.
        GList* list = evict();
        GList* cpy = list;
        setCacheSize(getCacheSize()-1);

        list = g_list_first(list);
        while(list){
            freeDnsRecord((DNSRecord*) list->data);
            list = g_list_next(list);
        }

        g_list_free(cpy);
    }
}

int DNSTTLCache::put_into_cache(DNSRecord* record){
    // calculate the hash, check if it's already in the cache.

    if(!record->rdata){
        throw cRuntimeError("Retrieved invalid record to put into cache");
    }

    const char* type = getTypeStringForValue(record->rtype);
    const char* _class = getClassStringForValue(record->rclass);

    // create hash:
    char* hash = g_strdup_printf("%s:%s:%s", record->rname, type, _class);

    // check if it is in the cache
    if(!is_in_cache(hash)){
        if(DNSCache::getCacheSize() > DNSCache::getMaxRecords()){
            evict();
        }

        GList* list = NULL;
        DNSTimeRecord* time_record = (DNSTimeRecord*) malloc(sizeof(*time_record));

        time_record->record = record;
        time_record->hash = hash;
        time_record->rcv_time = simTime();

        char* stime = g_strdup_printf("%ds", record->ttl);
        simtime_t tv = simTime() + STR_SIMTIME(stime);
        g_free(stime);
        time_record->expiry = time_record->rcv_time + tv;

        //g_printf("DEBUG MSG: New hash entering CACHE --- [%s], for record->rname=%s\n", hash, record->rname);
        list = g_list_append(list, time_record);
        g_hash_table_insert(cache, hash, list);
        dnsRecordPriorityCache.insert(time_record);
        setCacheSize(getCacheSize()+1);
    }
    else{
        // check if the data is still the same
        GList* from_cache = (GList*) g_hash_table_lookup(cache, hash);
        from_cache = g_list_first(from_cache);

        int is_already_in_cache = 0;
        while(from_cache){
            DNSTimeRecord* record_from_cache = (DNSTimeRecord*) from_cache->data;

            if(!g_strcmp0(record->rdata, record_from_cache->record->rdata)){
                is_already_in_cache = 1;
                // update expiry by new data
                break;
            }

            from_cache = g_list_next(from_cache);
        }

        if(!is_already_in_cache){
            // create a new time record
            DNSTimeRecord* time_record = (DNSTimeRecord*) malloc(sizeof(*time_record));
            time_record->record = record;
            time_record->hash = hash;
            time_record->rcv_time = simTime();

            char* stime = g_strdup_printf("%ds", record->ttl);
            simtime_t tv = simTime() + STR_SIMTIME(stime);
            g_free(stime);
            time_record->expiry = time_record->rcv_time + tv;
            // replace the entry in the database
            from_cache = (GList*) g_hash_table_lookup(cache, hash);
            from_cache = g_list_append(from_cache, time_record);
            g_hash_table_replace(cache, hash, from_cache);
            dnsRecordPriorityCache.insert(time_record);
        }
        else{
            g_free(hash);
        }
    }

    return 1;

}

GList* DNSTTLCache::get_from_cache(char* hash){
    GList* from_cache = (GList*) g_hash_table_lookup(cache, hash);
    // create a list containing the DNSRecords
    GList* record_list = NULL;
    while(from_cache){
        record_list = g_list_append(record_list, ((DNSTimeRecord*) from_cache->data)->record);

        from_cache = g_list_next(from_cache);
    }

    return record_list;

}

int DNSTTLCache::is_in_cache(char* hash){
    return g_hash_table_contains(cache, hash);
}

int DNSTTLCache::halfTTL(DNSRecord* r){
    // get the time record list for the hash from the cache
    const char* type = getTypeStringForValue(r->rtype);
    const char* _class = getClassStringForValue(r->rclass);

    // create hash:
    char* hash = g_strdup_printf("%s:%s:%s", r->rname, type, _class);
    GList* tr_list = (GList*) g_hash_table_lookup(cache, hash);
    while(tr_list){
        DNSTimeRecord* tr = (DNSTimeRecord*) tr_list->data;
        DNSRecord* record = tr->record;

        if(!g_strcmp0(record->rdata, r->rdata) && r->rtype == record->rtype && record->rclass == r->rclass){
            char* stime = g_strdup_printf("%ds", r->ttl);
            simtime_t ttl_to_sim = STR_SIMTIME(stime);
            g_free(stime);
            simtime_t curr = simTime();
            if((tr->expiry - curr).inUnit(-3) < (ttl_to_sim / 2).inUnit(-3)){
                g_free(hash);
                return 0; // less than half ttl left
            }
            else{
                g_free(hash);
                return 1;
            }
        }

        tr_list = g_list_next(tr_list);
    }

    return 0;
}

GList* DNSTTLCache::cleanup(){
    std::set<ODnsExtension::DNSTimeRecord*>::iterator iterator;
    GList* returnlist = NULL;
    for(iterator = dnsRecordPriorityCache.begin(); iterator != dnsRecordPriorityCache.end(); iterator++){
        DNSTimeRecord* r = *iterator;
        if(r->expiry < simTime()){
            // remove from caches
            dnsRecordPriorityCache.erase(r);
            DNSRecord* removed_record = remove_from_cache(r->hash, r->record);
            returnlist = g_list_append(returnlist, removed_record);
        }
        else{
            break; // we're finished cleaning up.
        }
    }

    return returnlist;
}

GList* DNSTTLCache::remove_from_cache(char* hash){
    GList* from_cache = get_from_cache(hash);
    if(from_cache){
        g_hash_table_remove(cache, hash);
        setCacheSize(getCacheSize()-1);

        // remove all time records from the priority queue ..
        while(from_cache){
            dnsRecordPriorityCache.erase((DNSTimeRecord*) from_cache->data);
            from_cache = g_list_next(from_cache);
        }

        return from_cache;
    }
    return NULL;
}

DNSRecord* DNSTTLCache::remove_from_cache(char* hash, DNSRecord* r){
    GList* from_cache = (GList*) g_hash_table_lookup(cache, hash);

    while(from_cache){
        DNSTimeRecord* tr = (DNSTimeRecord*) from_cache->data;

        if(!g_strcmp0(tr->record->rdata, r->rdata) && r->rtype == tr->record->rtype && tr->record->rclass == r->rclass){
            // we have the record
            from_cache = g_list_remove(g_list_first(from_cache), tr);
            // replace the list in the table
            g_hash_table_replace(cache, hash, from_cache);
            // free the time record, return the record
            DNSRecord* return_record = tr->record;
            remove_time_record(tr);
            free(tr);
            return return_record;
        }

        from_cache = g_list_next(from_cache);
    }

    // this means we did not find the record, return NULL
    return NULL;
}



void DNSTTLCache::remove_time_record(DNSTimeRecord* tr)
{
    std::set<ODnsExtension::DNSTimeRecord*, ODnsExtension::DNSTimeRecordComparator>::iterator it;

    for(it = dnsRecordPriorityCache.begin(); it != dnsRecordPriorityCache.end(); it++){
        if(*it == tr){
            dnsRecordPriorityCache.erase(it++);
            continue;
        }
    }
}

GList* DNSTTLCache::evict(){
    if(getCacheSize() == 0){
        return NULL;
    }

    // evict top element...
    ODnsExtension::DNSTimeRecord* top = *dnsRecordPriorityCache.begin();

    return remove_from_cache(top->hash);
}

GList* DNSTTLCache::get_matching_hashes(char* hash){
    GList* hash_list = NULL;
    GHashTableIter iterator;
    g_hash_table_iter_init(&iterator, cache);
    gpointer key, value;

    while(g_hash_table_iter_next(&iterator, &key, &value)){
        if(g_str_has_suffix(hash, (char*) key)){
            // we have a match, append it to the return list
            char* hash_cpy = g_strdup((char*) key);
            hash_list = g_list_append(hash_list, hash_cpy);
        }
    }

    return hash_list;

}

}
