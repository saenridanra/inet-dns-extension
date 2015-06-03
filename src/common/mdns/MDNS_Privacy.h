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
 * @file MDNS_Privacy.h
 *
 * Contains functions and structures needed for the functionalities provided
 * by the mdns privacy extension.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */

#ifndef __INETDNS_MDNS_PRIVACY_H_
#define __INETDNS_MDNS_PRIVACY_H_

#include <omnetpp.h>

#include "IPvXAddressResolver.h"
#include <DNSTools.h>
#include <DNS.h>
#include <MDNS.h>

#include <regex>
#include <list>
#include <memory>

namespace INETDNS{

/**
 * @brief Structure holding data for a private MDNS service
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct PrivateMDNSService{

    /**
     * @brief The type of the service.
     */
    std::string service_type;

    /**
     * @brief Whether the service is private.
     */
    int is_private;

    /**
     * @brief List of friend ids this service is offered to.
     */
    std::list<std::string> offered_to;

    /**
     * @brief List of friend ids this service is offered by.
     */
    std::list<std::string> offered_by;

    PrivateMDNSService(): service_type(""), is_private(0) {};

} private_mdns_service;

/**
 * @brief Structure holding pairing data
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct PairingData{

    /**
     * @brief A string valued crypto key used for encryption.
     *
     * Currently not used.
     */
    std::string crypto_key;

    /**
     * @brief String valued id of a "friend"
     */
    std::string friend_id;

    /**
     * @brief String valued instance name for the privacy service.
     */
    std::string privacy_service_instance_name;

    PairingData() : crypto_key(""), friend_id(""), privacy_service_instance_name("") {};
} pairing_data;

/**
 * @brief Structure holding friend data
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct FriendData{

    /**
     * @brief PairingData object belonging to this friend
     */
    std::shared_ptr<PairingData> pdata;

    /**
     * @brief The address of the friend
     */
    IPvXAddress address;

    /**
     * @brief The port on which the friend privacy socket listens to
     */
    int port;

    /**
     * @brief Time when the last announcment of the friends privacy service was received.
     */
    simtime_t last_informed;

    /**
     * @brief Whether the friend is currently online.
     */
    int online;

    FriendData () : port(0), last_informed(0), online(0) {};

} friend_data;

/**
 * @brief Extracts the service type from a query
 *
 * For a given query of the form instance._service._proto.local
 * extracts _service._proto.local.
 *
 * @param label the query
 *
 * @return returns the service type
 */
std::string extract_stype(std::string label);

/**
 * @brief Convenience method to create a @ref PrivateMDNSService
 *
 * @param service_type The service type string
 * @param is_private whether the service is private
 *
 * @return Smart pointer to newly created private service.
 *
 */
std::shared_ptr<PrivateMDNSService> private_service_new(std::string service_type, int is_private);

/**
 * @brief Convenience method to create a @ref PairingData
 *
 * @param crypto_key The key used to encrypt data
 * @param friend_id The friends id
 * @param privacy_instance_name The instance name of the privacy service.
 *
 * @return Smart pointer to newly created pairing data.
 *
 */
std::shared_ptr<PairingData> pairing_data_new(std::string crypto_key, std::string friend_id, std::string privacy_instance_name);

/**
 * @brief Convenience method to create a @ref FriendData
 *
 * @param pdata The pairing data belonging to this friend.
 * @param port The port on which the friends privacy socket listens to.
 *
 * @return Smart pointer to newly created friend data.
 *
 */
std::shared_ptr<FriendData> friend_data_new(std::shared_ptr<PairingData> pdata, int port);

#define DEFAULT_PRIVACY_SOCKET_PORT 9977

}

#endif /* __inet_dns_extension_MDNS_PRIVACY_H_ */
