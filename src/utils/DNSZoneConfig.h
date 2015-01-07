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

#ifndef __OPP_DNS_EXTENSION_DNSSERVERBASE_H_
#define __OPP_DNS_EXTENSION_DNSSERVERBASE_H_

#include <omnetpp.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <glib.h>

typedef struct soa{
    char* mname;
    char* rname;
    int serial;
    int refresh;
    int retry;
    int expire;
    int minimum;
} soa;

typedef struct zone_entry{
    char* domain;
    char* __class;
    char* type;
    char* data;
} zone_entry;

guint zone_entry_destroy(gpointer _entry);

enum states{
    VARS,
    SOA,
    ENTRY
};

/**
 * @brief DNSZoneConfig reads a zone configuration file
 * and initializes the data into internal data structures.
 */
class DNSZoneConfig {

public:

protected:
    std::string config_file;
    int TTL;
    int state;

    /**
     * Catalog definitions
     */
    std::string origin;
    GHashTable* zone_catalog;

    // some reference vectors for the most common
    // dns types.
    std::vector<char*> ns_entries;
    std::vector<char*> mx_entries;
    std::vector<char*> a_entries;
    std::vector<char*> aaaa_entries;
    std::vector<char*> cname_entries;

    soa* zone_soa;


public:
    DNSZoneConfig();
    virtual ~DNSZoneConfig();
    virtual void finish();

    virtual void initialize(std::string config_file);

    virtual int getTTL();
    struct soa* getSOA();
    struct zone_entry* getEntry(std::string domain);
    virtual GHashTable* getEntries();

};

#endif

