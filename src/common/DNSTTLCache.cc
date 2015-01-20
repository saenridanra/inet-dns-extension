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
            freeDnsRecord(((DNSTimeRecord*) list->data)->record);
            g_free((DNSRecord*) list->data);
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
            // evict and free 10% of the records.
            for(int i=0; i < floor(DNSCache::getMaxRecords()/10); i++){
                DNSTimeRecord* time_record = *dnsRecordPriorityCache.begin();
                dnsRecordPriorityCache.erase(time_record);
                GList* list = remove_from_cache(time_record->hash);
                list = g_list_first(list);
                while(list){
                    freeDnsRecord((DNSRecord*) list->data);
                    free((DNSRecord*) list->data);
                }
                free(time_record);

            }
        }

        GList* list = NULL;
        list = g_list_append(list, (gpointer) record);
        DNSTimeRecord* time_record = (DNSTimeRecord*) malloc(sizeof(time_record));

        time_record->record = record;
        time_record->hash = hash;
        time_record->rcv_time = simTime();

        char* stime = g_strdup_printf("%ds", record->ttl);
        simtime_t tv = simTime() + STR_SIMTIME(stime);
        g_free(stime);
        time_record->expiry = time_record->rcv_time + tv;

        //g_printf("DEBUG MSG: New hash entering CACHE --- [%s], for record->rname=%s\n", hash, record->rname);
        g_hash_table_insert(cache, hash, (gpointer) list);
        dnsRecordPriorityCache.insert(time_record);
        setCacheSize(getCacheSize()+1);
    }
    else{
        // check if the data is still the same
        GList* from_cache = (GList*) g_hash_table_lookup(cache, hash);
        from_cache = g_list_first(from_cache);

        int is_already_in_cache = 0;
        while(from_cache){
            DNSRecord* record_from_cache = (DNSRecord*) from_cache->data;

            if(g_strcmp0(record->rdata, record_from_cache->rdata) == 0){
                is_already_in_cache = 1;
                break;
            }

            from_cache = g_list_next(from_cache);
        }

        if(!is_already_in_cache){
            // append the record
            from_cache = (GList*) g_hash_table_lookup(cache, hash);
            from_cache = g_list_append(from_cache, (gpointer) record);

            // replace the entry in the database
            g_hash_table_replace(cache, hash, (gpointer) from_cache);


            DNSTimeRecord* time_record = (DNSTimeRecord*) malloc(sizeof(time_record));
            time_record->record = record;
            time_record->hash = hash;
            time_record->rcv_time = simTime();

            char* stime = g_strdup_printf("%ds", record->ttl);
            simtime_t tv = simTime() + STR_SIMTIME(stime);
            g_free(stime);
            time_record->expiry = time_record->rcv_time + tv;
        }
        else{
            // update expiry and rcv time of the record
            // thereby removing it, and adding it again for update
            // of the priority set
            g_free(hash);
        }
    }

    return 1;

}

GList* DNSTTLCache::get_from_cache(char* hash){
    GList* from_cache = (GList*) g_hash_table_lookup(cache, hash);
    if(from_cache){
        return from_cache;
    }

    return NULL;

}

int DNSTTLCache::halfTTL(DNSRecord* r){
    // this is very inefficient, a reverse map would be better,
    // but for now this has to suffice..
    std::set<ODnsExtension::DNSTimeRecord*>::iterator iterator;
    for(iterator = dnsRecordPriorityCache.begin(); iterator != dnsRecordPriorityCache.end(); iterator++){
        DNSTimeRecord* in_cache = *iterator;
        if(r == in_cache->record){
            char* stime = g_strdup_printf("%ds", in_cache->record->ttl);
            simtime_t tv = simTime() + STR_SIMTIME(stime);
            if((in_cache->expiry - in_cache->rcv_time) / tv < 0.5)
                return 0;
            else
                return 1;
        }
    }

    throw cRuntimeError("Checked for DNSRecord TTL, but not included in priority cache");
}

int DNSTTLCache::is_in_cache(char* hash){
    if(g_hash_table_contains(cache, hash)){
        return 1;
    }

    return 0;
}

void DNSTTLCache::cleanup(){
    std::set<ODnsExtension::DNSTimeRecord*>::iterator iterator;
    for(iterator = dnsRecordPriorityCache.begin(); iterator != dnsRecordPriorityCache.end(); iterator++){
        DNSTimeRecord* r = *iterator;
        if(r->expiry > simTime()){
            // remove from caches
            dnsRecordPriorityCache.erase(r);
            GList* list = remove_from_cache(r->hash);
            list = g_list_first(list);
            while(list){
                freeDnsRecord((DNSRecord*) list->data);
                free((DNSRecord*) list->data);
            }
            free(r);
        }
        else{
            break; // we're finished cleaning up.
        }
    }
}

GList* DNSTTLCache::remove_from_cache(char* hash){
    GList* from_cache = (GList*) g_hash_table_lookup(cache, hash);
    if(from_cache){
        g_hash_table_remove(cache, hash);
        setCacheSize(getCacheSize()-1);
        return from_cache;
    }
    return NULL;
}

GList* DNSTTLCache::evict(){
    if(getCacheSize() == 0){
        return 0;
    }

    // evict top element...
    ODnsExtension::DNSTimeRecord* top = *dnsRecordPriorityCache.begin();
    dnsRecordPriorityCache.erase(top);

    return remove_from_cache(top->hash);
}

}
