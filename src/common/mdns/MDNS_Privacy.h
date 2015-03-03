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

#ifndef MDNS_PRIVACY_H_
#define MDNS_PRIVACY_H_

#include <omnetpp.h>

#include "IPvXAddressResolver.h"
#include <DNSTools.h>
#include <DNS.h>
#include <MDNS.h>

#include <glib.h>

namespace ODnsExtension{

typedef struct PrivateMDNSService{
    const char* service_type;
    int is_private;
    GList* offered_to;
    GList* offered_by;
} private_mdns_service;

typedef struct PairingData{
    const char* crypto_key;
    const char* friend_id;
    const char* privacy_service_instance_name;
} pairing_data;

typedef struct FriendData{
    PairingData* pdata;
    IPvXAddress address;
    int port;
    simtime_t last_informed;
} friend_data;

char* extract_stype(char* label);
PrivateMDNSService* private_service_new(const char* service_type, int is_private);
PairingData* pairing_data_new(const char* crypto_key, const char* friend_id, const char* privacy_instance_name);
FriendData* friend_data_new(PairingData* pdata, int port);

#define DEFAULT_PRIVACY_SOCKET_PORT 9977

}

#endif /* MDNS_PRIVACY_H_ */
