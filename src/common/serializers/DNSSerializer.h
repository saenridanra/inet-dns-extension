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
#ifndef DNSSERIALIZER_H_
#define DNSSERIALIZER_H_

#include <INETDefs.h>
#include <DNS.h>
#include <DNSPacket_m.h>
#include "inet/common/serializer/SerializerBase.h"
#include <unordered_map>

namespace inet {

namespace serializer {

/**
 * @brief Converts between @ref INETDNS::DNSPacket and the binary
 * representation of dns packets.
 */
class DNSSerializer : public SerializerBase{
protected:

  // @brief Maps label record starting points to offsets.
  std::unordered_map<std::string, unsigned short>  label_offsets;

  virtual void serialize(const cPacket *pkt, Buffer &b, Context& context) override;
  virtual cPacket * deserialize(const Buffer &b, Context& context) override;

  virtual void serialize_question(INETDNS::DNSQuestion *question, Buffer &b);
  virtual void serialize_answer(INETDNS::DNSRecord *record, Buffer &b);
  virtual void serialize_name(std::string str, Buffer &b, bool is_name);
  virtual void serialize_data_string(std::string str, Buffer &b);
public:
    DNSSerializer(const char *name = nullptr) : inet::serializer::SerializerBase(name){}
};

}

}
#endif /* DNSSERIALIZER_H_ */