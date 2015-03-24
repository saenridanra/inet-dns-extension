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

#ifndef __OPP_DNS_EXTENSION_MDNS_PRIVACY_H_
#define __OPP_DNS_EXTENSION_MDNS_PRIVACY_H_

#include <omnetpp.h>

#include "IPvXAddressResolver.h"
#include <DNSTools.h>
#include <DNS.h>
#include <MDNS.h>

#include <regex>
#include <list>
#include <memory>

namespace ODnsExtension{

typedef struct PrivateMDNSService{
    std::string service_type;
    int is_private;
    std::list<std::string> offered_to;
    std::list<std::string> offered_by;

    PrivateMDNSService(): service_type(""), is_private(0) {};

} private_mdns_service;

typedef struct PairingData{
    std::string crypto_key;
    std::string friend_id;
    std::string privacy_service_instance_name;

    PairingData() : crypto_key(""), friend_id(""), privacy_service_instance_name("") {};
} pairing_data;

typedef struct FriendData{
    std::shared_ptr<PairingData> pdata;
    IPvXAddress address;
    int port;
    simtime_t last_informed;
    int online;

    FriendData () : port(0), last_informed(0), online(0) {};

} friend_data;

std::string extract_stype(std::string label);
std::shared_ptr<PrivateMDNSService> private_service_new(std::string service_type, int is_private);
std::shared_ptr<PairingData> pairing_data_new(std::string crypto_key, std::string friend_id, std::string privacy_instance_name);
std::shared_ptr<FriendData> friend_data_new(std::shared_ptr<PairingData> pdata, int port);

#define DEFAULT_PRIVACY_SOCKET_PORT 9977

}

#endif /* __OPP_DNS_EXTENSION_MDNS_PRIVACY_H_ */
