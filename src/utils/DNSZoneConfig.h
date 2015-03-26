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

#ifndef __OPP_DNS_EXTENSION_DNSZONECONFIG_H_
#define __OPP_DNS_EXTENSION_DNSZONECONFIG_H_

#include <omnetpp.h>

#include "utils/Utils.h"

#include <iostream>
#include <vector>
#include <string>
#include <list>
#include <unordered_map>
#include <memory>
#include <algorithm>
#include <fstream>

typedef struct soa{
    std::string mname;
    std::string rname;
    int serial;
    int refresh;
    int retry;
    int expire;
    int minimum;

    soa() : mname(""), rname(""), serial(0), refresh(0), retry(0), expire(0), minimum(0) {}
} soa;

typedef struct zone_entry{
    std::string domain;
    std::string __class;
    std::string type;
    std::string data;

    zone_entry() : domain(""), __class(""), type(""), data("") {}
} zone_entry;

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
    std::unordered_map<std::string, std::list<std::shared_ptr<zone_entry>>> zone_catalog;

    std::shared_ptr<soa> zone_soa;


public:
    DNSZoneConfig();
    virtual ~DNSZoneConfig();
    virtual void finish();

    virtual void initialize(std::string config_file);

    virtual int getTTL();
    std::shared_ptr<soa> getSOA();
    virtual std::string getOrigin();
    int hasEntry(std::string hash);
    std::list<std::shared_ptr<zone_entry>> getEntry(std::string hash);
    virtual std::unordered_map<std::string, std::list<std::shared_ptr<zone_entry>>>* getEntries();

};

#endif

