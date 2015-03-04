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

#include <MDNS_Privacy.h>

namespace ODnsExtension{

GRegex* privacy_regex = NULL;
GError* regex_error = NULL;
GMatchInfo* regex_match_info = NULL;

char* extract_stype(char* label){
    // compile once
    if(privacy_regex == NULL){
        const char* privacy_type_expr = "_.+\\._.+\\.local";
        privacy_regex = g_regex_new(privacy_type_expr, G_REGEX_CASELESS, G_REGEX_MATCH_NOTEMPTY, &regex_error);
    }

    char* match = NULL;
    g_regex_match(privacy_regex, label, g_regex_get_match_flags(privacy_regex), &regex_match_info);
    if (g_match_info_matches(regex_match_info)) {
        match = g_match_info_fetch(regex_match_info, 0);
    }

    if(match == NULL) match = g_strdup("");
    return match;
}

ODnsExtension::PrivateMDNSService* private_service_new(char* service_type, int is_private){
    ODnsExtension::PrivateMDNSService* service = (ODnsExtension::PrivateMDNSService*) malloc(sizeof(*service));
    service->service_type = service_type;
    service->is_private = is_private;
    return service;
}

ODnsExtension::PairingData* pairing_data_new(char* crypto_key, char* friend_id, char* privacy_instance_name){
    ODnsExtension::PairingData* pdata = (ODnsExtension::PairingData*) malloc(sizeof(*pdata));
    pdata->crypto_key = crypto_key;
    pdata->friend_id = friend_id;
    pdata->privacy_service_instance_name = privacy_instance_name;

    return pdata;
}

ODnsExtension::FriendData* friend_data_new(ODnsExtension::PairingData* pdata, int port){
    ODnsExtension::FriendData* fdata = (ODnsExtension::FriendData*) malloc(sizeof(*fdata));
    fdata->pdata = pdata;
    fdata->port = port;
    fdata->online = 0;
    return fdata;
}

}
