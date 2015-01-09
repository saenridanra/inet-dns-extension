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

#include <DNSZoneConfig.h>

DNSZoneConfig::DNSZoneConfig()
{
    zone_catalog = g_hash_table_new(g_str_hash, g_str_equal);
    TTL = 0;
    zone_soa = (soa*) malloc(sizeof(*zone_soa));
    state = states::VARS;
}

DNSZoneConfig::~DNSZoneConfig()
{
    g_hash_table_destroy(zone_catalog);
    free(zone_soa);
}

void DNSZoneConfig::initialize(std::string config_file){
    std::string line;
    std::string lastsuffix;
    zone_entry* e;
    char* namehash;

    std::fstream conf(config_file, std::ios::in);
    while(getline(conf, line, '\n'))
    {

#ifdef DEBUG_ENABLED
        printf("Processing:");
        printf("%s", line.c_str());
        printf("\n");
#endif

        if (line.empty() || line[0] == ';'){

#ifdef DEBUG_ENABLED
        printf("Skipping\n");
#endif

            continue;
        }

        // use a tokenizer to interpret the line
        std::vector<std::string> tokens = cStringTokenizer(line.c_str()).asVector();

#ifdef DEBUG_ENABLED
        printf("Number of tokens: %d \n", (int) tokens.size());

        for(uint32_t i = 0; i < tokens.size(); i++){
            printf("tokens[%d] = %s; ", i, tokens[i].c_str());
        }

        printf("\n");
#endif

        switch(state){
            case states::VARS:
                if (line[0] == '$'){
                    // This is a variable and the first two tokens are relevant, i.e.
                    //  $VAR  VALUE
                    if(tokens[0] == "$TTL")
                        TTL = std::stoi(tokens[1].substr(1));
                    else if(tokens[0] == "$ORIGIN"){
                        if(tokens[1].at(tokens[1].length() - 1) == '.'){
                            origin = g_strndup(tokens[1].c_str(), tokens[1].length()-1);
                        }
                        else{
                            origin = g_strdup(tokens[1].c_str());
                        }
                    }

                }
                else if(tokens[2] == "SOA"){
                    state = states::SOA;
#ifdef DEBUG_ENABLED
        printf("State set to \"SOA\"\n");
#endif
                    // init SOA first line
                    lastsuffix = tokens[0];
                    zone_soa->mname = g_strdup(tokens[3].c_str());
                    zone_soa->rname = g_strdup(tokens[4].c_str());

                }
                else{
                    // malformed?
                }
                break;
            case states::SOA:
                if(tokens[0] != ")"){
                    // init value
                    if(tokens[2] == "sn"){
                        zone_soa->serial = std::stoi(tokens[0]);
                    }
                    else if(tokens[2] == "ref"){
                        zone_soa->refresh = std::stoi(tokens[0]);
                    }
                    else if(tokens[2] == "ret"){
                        zone_soa->retry = std::stoi(tokens[0]);
                    }
                    else if(tokens[2] == "ex"){
                        zone_soa->expire = std::stoi(tokens[0]);
                    }
                    else if(tokens[2] == "nx"){
                        zone_soa->minimum = std::stoi(tokens[0]);
                    }
                }
                else{
                    state = states::ENTRY;
                }

                break;
            case states::ENTRY:
                if(tokens[0] == ";") break;

                // REMARK: Ignoring TTL in entries, or more precise,
                // not allowing it right now, so leave it out of the zone file
                // we use the last known suffix
                e = (zone_entry*) malloc(sizeof(*e));

                if(tokens[0] == "IN" || tokens[0] == "CS" || tokens[0] == "HS" || tokens[0] == "CH" || tokens[0] == "*"){
                    if(strcmp(lastsuffix.c_str(), "@") == 0){
                        e->domain = g_strdup(origin);
                    }
                    else{
                        e->domain = g_strdup(lastsuffix.c_str());
                    }
                    e->__class = g_strdup(tokens[0].c_str());
                    e->type =  g_strdup(tokens[1].c_str());

                    // remove trailing dot from entry..
                    if(tokens[2].at(tokens[2].length() - 1) == '.'){
                        e->data = g_strndup(tokens[2].c_str(), tokens[2].length()-1);
                    }
                    else{
                        e->data = g_strdup(tokens[2].c_str());
                    }
                }
                else{
                    // should start with the suffix
                    if(strcmp(tokens[0].c_str(), "@") == 0){
                        e->domain = g_strdup(origin);
                    }
                    else{
                        e->domain = g_strdup(tokens[0].c_str());
                    }
                    lastsuffix = e->domain;
                    e->__class =  g_strdup(tokens[1].c_str());
                    e->type =  g_strdup(tokens[2].c_str());

                    // remove trailing dot from entry..
                    if(tokens[3].at(tokens[3].length() - 1) == '.'){
                        e->data = g_strndup(tokens[3].c_str(), tokens[3].length()-1);
                    }
                    else{
                        e->data = g_strdup(tokens[3].c_str());
                    }
                }

                if(strcmp(e->domain, origin) != 0){
                    namehash = g_strdup_printf("%s.%s:%s:%s", e->domain, origin, e->type, e->__class);
                }
                else{
                    namehash = g_strdup_printf("%s:%s:%s", e->domain, e->type, e->__class);
                }

                if(!g_hash_table_contains(zone_catalog, namehash)){
                    GList* first_element = NULL;
                    first_element = g_list_append(first_element, e);
                    g_hash_table_insert(zone_catalog, namehash, first_element);
                }
                else{
                    GList* list = (GList*) g_hash_table_lookup(zone_catalog, namehash);
                    list = g_list_append(list, e);
                }

                //g_free(namehash); // don't free the hash, it is needed for the hash table..

#ifdef DEBUG_ENABLED
        printf("Inserted %s into hashtable\n", namehash);
#endif

                break;

            default: break;
        }
    }

#ifdef DEBUG_ENABLED
        printf("Fully initialized zone configuration.");
#endif
}

int DNSZoneConfig::getTTL(){
    return TTL;
}

struct soa* DNSZoneConfig::getSOA(){
    return zone_soa;
}

GList* DNSZoneConfig::getEntry(char* hash){
    GList* e = (GList*)g_hash_table_lookup(zone_catalog, hash);
    return e;
}

int DNSZoneConfig::hasEntry(char* hash){
    return g_hash_table_contains(zone_catalog, hash);
}

GHashTable* DNSZoneConfig::getEntries(){
    return zone_catalog;
}

void DNSZoneConfig::finish(){
    this->~DNSZoneConfig();
}

char* DNSZoneConfig::getOrigin(){
    return origin;
}

guint zone_entry_destroy(gpointer _entry){
    zone_entry *entry = (zone_entry*) _entry;

    g_free(entry->domain);
    g_free(entry->type);
    g_free(entry->__class);
    g_free(entry->data);
    free(entry);

    return 0;
}
