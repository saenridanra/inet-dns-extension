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
    zone_soa = (soa*) malloc(sizeof(soa));
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
    struct zone_entry* e;
    std::string namehash;

    std::fstream conf(config_file, std::ios::in);
    while(getline(conf, line, '\n'))
    {
        if (line.empty() || line[0] == '#')
            continue;

        // use a tokenizer to interpret the line
        std::vector<std::string> tokens = cStringTokenizer(line.c_str()).asVector();

        switch(state){
            case states::VARS:
                if (line[0] == '$'){
                    // This is a variable and the first two tokens are relevant, i.e.
                    //  $VAR  VALUE
                    if(tokens[0] == "$TTL")
                        TTL = std::stoi(tokens[1].substr(1));
                    else if(tokens[0] == "$ORIGIN")
                        origin = tokens[1];

                }
                else if(line[0] == ';'){
                    // do nothing at the moment ..
                }
                else if(tokens[2] == "SOA"){
                    state = states::SOA;
                    // init SOA first line
                    lastsuffix = tokens[0];
                    zone_soa->mname = tokens[3];
                    zone_soa->rname = tokens[4];
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
                e = (zone_entry*) malloc(sizeof(zone_entry*));

                if(tokens[0] == "IN" || tokens[0] == "CS" || tokens[0] == "HS" || tokens[0] == "CH" || tokens[0] == "*"){
                    e->domain = lastsuffix;
                    e->__class = tokens[0];
                    e->type = tokens[1];
                    e->data = tokens[2];
                }
                else{
                    // should start with the suffix
                    e->domain = tokens[0];
                    lastsuffix = e->domain;
                    e->__class = tokens[1];
                    e->type = tokens[2];
                    e->data = tokens[3];
                }

                namehash = e->domain+":"+e->type;
                g_hash_table_insert(zone_catalog, (char*) namehash.c_str(), e);

                // we have special vectors for the following..
                if(e->type == "NS"){
                    ns_entries.push_back((e->domain+":"+e->type));
                }
                else if(e->type == "MX"){
                    mx_entries.push_back((e->domain+":"+e->type));
                }
                else if(e->type == "A"){
                    a_entries.push_back((e->domain+":"+e->type));
                }
                else if(e->type == "AAAA"){
                    aaaa_entries.push_back((e->domain+":"+e->type));
                }
                else if(e->type == "CNAME"){
                    cname_entries.push_back((e->domain+":"+e->type));
                }
                break;

            default: break;
        }
    }
}

int DNSZoneConfig::getTTL(){
    return TTL;
}

struct soa* DNSZoneConfig::getSOA(){
    return zone_soa;
}

struct zone_entry* DNSZoneConfig::getEntry(std::string domain){
    struct zone_entry* e = (zone_entry*)g_hash_table_lookup(zone_catalog, &domain);
    return e;
}

GHashTable* DNSZoneConfig::getEntries(){
    return zone_catalog;
}
