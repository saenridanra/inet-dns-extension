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

namespace ODnsExtension {

std::regex privacy_type_expr ("(.*)(_.+\\._.+\\.local)");

std::string extract_stype(std::string label)
{
    // compile once
    std::string match;
    auto m = std::smatch{};
    if (std::regex_match(label, m, privacy_type_expr))
    {
        match = m[2].str();
    }

    return match;
}

std::shared_ptr<ODnsExtension::PrivateMDNSService> private_service_new(std::string service_type, int is_private)
{
    std::shared_ptr<ODnsExtension::PrivateMDNSService> service(new ODnsExtension::PrivateMDNSService);
    service->service_type = service_type;
    service->is_private = is_private;
    return service;
}

std::shared_ptr<ODnsExtension::PairingData> pairing_data_new(std::string crypto_key, std::string friend_id, std::string privacy_instance_name)
{
    std::shared_ptr<ODnsExtension::PairingData> pdata(new ODnsExtension::PairingData);
    pdata->crypto_key = crypto_key;
    pdata->friend_id = friend_id;
    pdata->privacy_service_instance_name = privacy_instance_name;

    return pdata;
}

std::shared_ptr<ODnsExtension::FriendData> friend_data_new(std::shared_ptr<ODnsExtension::PairingData> pdata, int port)
{
    std::shared_ptr<ODnsExtension::FriendData> fdata(new ODnsExtension::FriendData);
    fdata->pdata = pdata;
    fdata->port = port;
    fdata->online = 0;
    fdata->last_informed = STR_SIMTIME("0s");
    return fdata;
}

}
