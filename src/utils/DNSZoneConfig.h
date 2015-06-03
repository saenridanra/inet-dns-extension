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

/**
 * @file DNSZoneConfig.h
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
#ifndef __INETDNS_DNSZONECONFIG_H_
#define __INETDNS_DNSZONECONFIG_H_

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


/** @brief Structure holding information for a soa entry
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct soa{
    /**
     * @brief The soas actual domain name as a string value.
     *
     * The <domain-name> of the name server that was the
     * original or primary source of data for this zone.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    std::string mname;

    /**
     * @brief String value for the mail address of the soa.
     *
     * A <domain-name> which specifies the mailbox of the
     * person responsible for this zone.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    std::string rname;

    /**
     * @brief Version number
     *
     * The unsigned 32 bit version number of the original copy
     * of the zone.  Zone transfers preserve this value.  This
     * value wraps and should be compared using sequence space
     * arithmetic.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    int serial;

    /**
     * @brief Refresh interval
     *
     * A 32 bit time interval before the zone should be
     * refreshed.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    int refresh;

    /**
     * @brief Retry interval
     *
     * A 32 bit time interval that should elapse before a
     * failed refresh should be retried.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    int retry;

    /**
     * @brief Expiry interval
     *
     * A 32 bit time value that specifies the upper limit on
     * the time interval that can elapse before the zone is no
     * longer authoritative.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    int expire;

    /**
     * @brief Mimimum ttl value
     *
     * The unsigned 32 bit minimum TTL field that should be
     * exported with any RR from this zone.
     *
     * @see RFC 1035 <http://tools.ietf.org/html/rfc1035.txt>.
     */
    int minimum;

    soa() : mname(""), rname(""), serial(0), refresh(0), retry(0), expire(0), minimum(0) {}
} soa;

/** @brief Structure holding information for a zone entry
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct zone_entry{

    /**
     * @brief the domain name of the zone entry
     */
    std::string domain;

    /**
     * @brief the dns class value for the zone entry
     */
    std::string __class;

    /**
     * @brief the dns type value for the zone entry
     */
    std::string type;

    /**
     * @brief the data (target) the zone entry points to
     */
    std::string data;

    zone_entry() : domain(""), __class(""), type(""), data("") {}
} zone_entry;

enum states{
    VARS,
    SOA,
    ENTRY
};

/**
 * @brief DNSZoneConfig reads a zone configuration file and initializes the data into internal data structures.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class DNSZoneConfig {

public:

protected:

    /**
     * @brief The path to the configuration file
     *
     * Defined as a parameter to the ned file.
     */
    std::string config_file;

    /**
     * @brief The default ttl value
     */
    int TTL;

    /**
     * @brief The state of @ref DNSZoneConfig while initializing the file.
     */
    int state;

    /**
     * @brief The origin of this zone
     */
    std::string origin;

    /**
     * @brief A map from hashes to zone entries containing the records defined in the zone file.
     */
    std::unordered_map<std::string, std::list<std::shared_ptr<zone_entry>>> zone_catalog;

    /**
     * @brief The zone soa for this zone.
     */
    std::shared_ptr<soa> zone_soa;


public:
    DNSZoneConfig();
    virtual ~DNSZoneConfig();
    virtual void finish();

    virtual void initialize(std::string config_file);

    /**
     * @brief Get the default TTL for this zone.
     *
     * @return default ttl value
     */
    virtual int getTTL();

    /**
     * @brief Get the soa for this zone.
     *
     * @return @ref soa
     */
    std::shared_ptr<soa> getSOA();

    /**
     * @brief get the origin of this zone.
     *
     * @return The origin as a string.
     */
    virtual std::string getOrigin();

    /**
     * @brief Check whether this zone contains an entry
     *
     * @param hash String valued hash to look up
     *
     * @return 1 if there is an entry, 0 otherwise
     */
    int hasEntry(std::string hash);

    /**
     * @brief Get a list of entries
     *
     * @param hash String valued hash
     *
     * @return A list of @ref zone_entry for the given hash
     */
    std::list<std::shared_ptr<zone_entry>> getEntry(std::string hash);

    /**
     * @brief Retrieve the zone catalog
     *
     * @return A pointer to the zone catalog.
     */
    virtual std::unordered_map<std::string, std::list<std::shared_ptr<zone_entry>>>* getEntries();

};

#endif

