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

namespace ODnsExtension {

DNSSimpleCache::DNSSimpleCache() {
    // we don't need to destroy  the record in the hashfunc, since the evction
    // returns the record. If necessary it will be deleted
    cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    setCacheSize(0);
}

DNSSimpleCache::~DNSSimpleCache() {
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

int DNSSimpleCache::put_into_cache(DNSRecord* record){
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
                GList* list = evict();
                setCacheSize(getCacheSize()-1);

                list = g_list_first(list);
                while(list){
                    freeDnsRecord((DNSRecord*) list->data);
                    list = g_list_next(list);
                }
            }
        }

        GList* list = NULL;
        list = g_list_append(list, record);
        //g_printf("DEBUG MSG: New hash entering CACHE --- [%s], for record->rname=%s\n", hash, record->rname);
        g_hash_table_insert(cache, hash, list);
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
        }
        else{
            g_free(hash);
        }
    }

    return 1;


}

GList* DNSSimpleCache::get_from_cache(char* hash){
    GList* from_cache = (GList*) g_hash_table_lookup(cache, hash);
    if(from_cache){
        return from_cache;
    }

    return NULL;

}

int DNSSimpleCache::is_in_cache(char* hash){
    return g_hash_table_contains(cache, hash);
}

GList* DNSSimpleCache::remove_from_cache(char* hash){
    GList* from_cache = (GList*) g_hash_table_lookup(cache, hash);
    if(from_cache){
        g_hash_table_remove(cache, hash);
        setCacheSize(getCacheSize()-1);
        return from_cache;
    }
    return NULL;
}

GList* DNSSimpleCache::evict(){
    if(getCacheSize() == 0){
        return 0;
    }
    char* eviction_key;

    int p = intrand(getCacheSize());
    eviction_key = (char*) (g_list_nth(g_hash_table_get_keys(cache), p)->data);

    return remove_from_cache(eviction_key);
}

DNSRecord* DNSSimpleCache::remove_from_cache(char* hash, DNSRecord* r){
    GList* from_cache = (GList*) g_hash_table_lookup(cache, hash);
    g_list_remove(from_cache, r);
    return r;
}

GList* DNSSimpleCache::get_matching_hashes(char* hash){
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


} /* namespace ODnsExtension */
