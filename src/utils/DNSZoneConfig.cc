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
    config_file = "";
    origin = "";
    TTL = 0;
    zone_soa = std::shared_ptr<soa>(new soa());
    state = states::VARS;
}

DNSZoneConfig::~DNSZoneConfig()
{

}

void DNSZoneConfig::initialize(std::string config_file)
{
    std::string line;
    std::string lastsuffix;
    std::shared_ptr<zone_entry> e;
    std::string namehash;

    std::fstream conf(config_file, std::ios::in);
    while (getline(conf, line, '\n'))
    {

#ifdef DEBUG_ENABLED
        std::cout << "Processing:" << line << std::endl;
#endif

        if (line.empty() || line[0] == ';')
        {

#ifdef DEBUG_ENABLED
            std::cout << "Skipping" << std::endl;
#endif

            continue;
        }

        // use a tokenizer to interpret the line
        std::vector<std::string> tokens = cStringTokenizer(line.c_str()).asVector();

        if (tokens.size() == 0)
        {
            continue; // only white spaces in this line ..
        }

#ifdef DEBUG_ENABLED
        std::cout << "Number of tokens: " << tokens.size() << std::endl;

        for(uint32_t i = 0; i < tokens.size(); i++)
        {
            std::cout << "tokens[" << i << "] = " << tokens[i] << "; " << std::endl;
        }

#endif

        switch (state)
        {
            case states::VARS:
                if (line[0] == '$')
                {
                    // This is a variable and the first two tokens are relevant, i.e.
                    //  $VAR  VALUE
                    if (tokens[0] == "$TTL")
                        TTL = std::stoi(tokens[1].substr(1));
                    else if (tokens[0] == "$ORIGIN")
                    {
                        origin = std::string(tokens[1]);
                    }

                }
                else if (tokens[2] == "SOA")
                {
                    state = states::SOA;
#ifdef DEBUG_ENABLED
                    std::cout << "State set to \"SOA\"\n";
#endif
                    // init SOA first line
                    lastsuffix = std::string(tokens[0]);
                    zone_soa->mname = std::string(tokens[3]);
                    zone_soa->rname = std::string(tokens[4]);

                }
                else
                {
                    // malformed?
                }
                break;
            case states::SOA:
                if (tokens[0] != ")")
                {
                    // init value
                    if (tokens[2] == "sn")
                    {
                        zone_soa->serial = std::stoi(tokens[0]);
                    }
                    else if (tokens[2] == "ref")
                    {
                        zone_soa->refresh = std::stoi(tokens[0]);
                    }
                    else if (tokens[2] == "ret")
                    {
                        zone_soa->retry = std::stoi(tokens[0]);
                    }
                    else if (tokens[2] == "ex")
                    {
                        zone_soa->expire = std::stoi(tokens[0]);
                    }
                    else if (tokens[2] == "nx")
                    {
                        zone_soa->minimum = std::stoi(tokens[0]);
                    }
                }
                else
                {
                    state = states::ENTRY;
                }

                break;
            case states::ENTRY:
                if (tokens[0] == ";")
                    break;

                // REMARK: Ignoring TTL in entries, or more precise,
                // not allowing it right now, so leave it out of the zone file
                // we use the last known suffix
                e = std::shared_ptr<zone_entry>(new zone_entry());

                if (tokens[0] == "IN" || tokens[0] == "CS" || tokens[0] == "HS" || tokens[0] == "CH"
                        || tokens[0] == "*")
                {
                    if (lastsuffix == "@")
                    {
                        e->domain = std::string(origin);
                    }
                    else
                    {
                        e->domain = std::string(lastsuffix);
                    }
                    e->__class = std::string(tokens[0]);
                    e->type = std::string(tokens[1]);

                    e->data = std::string(tokens[2]);
                }
                else
                {
                    // should start with the suffix
                    if (tokens[0] == "@")
                    {
                        e->domain = std::string(origin);
                    }
                    else if (INETDNS::stdstr_has_suffix(tokens[0], std::string(".")))
                    {
                        e->domain = std::string(tokens[0]);
                    }
                    else
                    {
                        e->domain = std::string(tokens[0]) + "." + std::string(origin);
                    }

                    lastsuffix = std::string(tokens[0]);
                    e->__class = std::string(tokens[1]);
                    e->type = std::string(tokens[2]);
                    e->data = std::string(tokens[3]);

                }

                if (!INETDNS::stdstr_has_suffix(e->domain, std::string("."))
                        && !INETDNS::stdstr_has_suffix(e->domain, origin))
                {
                    namehash = e->domain + "." + origin + ":" + e->type + ":" + e->__class;
                }
                else
                {
                    namehash = e->domain + ":" + e->type + ":" + e->__class;
                }

                if(zone_catalog.find(namehash) != zone_catalog.end())
                {
                    std::list<std::shared_ptr<zone_entry>> list = zone_catalog[namehash];
                    list.push_back(e);
                    zone_catalog[namehash] = list;
                }
                else
                {
                    std::list<std::shared_ptr<zone_entry>> first_element;
                    first_element.push_back(e);
                    zone_catalog[namehash] = first_element;
                }

#ifdef DEBUG_ENABLED
                std::cout << "Inserted" << namehash << "into hashtable\n";
#endif

                break;

            default:
                break;
        }
    }

#ifdef DEBUG_ENABLED
    std::cout << "Fully initialized zone configuration.\n";
#endif
}

int DNSZoneConfig::getTTL()
{
    return TTL;
}

std::shared_ptr<soa> DNSZoneConfig::getSOA()
{
    return zone_soa;
}

std::list<std::shared_ptr<zone_entry>> DNSZoneConfig::getEntry(std::string hash)
{
    if(hasEntry(hash))
        return zone_catalog[hash];
    else
        return std::list<std::shared_ptr<zone_entry>>();
}

int DNSZoneConfig::hasEntry(std::string hash)
{
    return zone_catalog.find(hash) != zone_catalog.end();
}

std::unordered_map<std::string, std::list<std::shared_ptr<zone_entry>>>* DNSZoneConfig::getEntries()
{
    return &zone_catalog;
}

void DNSZoneConfig::finish()
{
    this->~DNSZoneConfig();
}

std::string DNSZoneConfig::getOrigin()
{
    return origin;
}
