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
 * @file MDNS.h
 *
 * Contains useful structs, makros and functions which are generally
 * needed for a MDNS library.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */


#ifndef OPP_DNS_EXTENSION_MDNS_H_
#define OPP_DNS_EXTENSION_MDNS_H_

#include <omnetpp.h>
#include <DNS.h>
#include <DNSTools.h>
#include "DNSPacket_m.h"
#include <list>
#include <memory>

namespace ODnsExtension {

/** @brief Structure holding information for services
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct MDNSService{
   /**
    * @brief The service type as a string.
    */
   std::string service_type;

   /**
    * @brief The instance name of the service as a string.
    */
   std::string name;

   /**
    * @brief A list of txtrecords as strings belonging to the service.
    */
   std::list<std::string> txtrecords;

   /**
    * @brief The port for which this service can be reached.
    */
   int   port;

   MDNSService() : service_type(""), name(""), port(-1) {}

} mdns_service;

/**
 * @brief A helper class containing few information needed for comparing mdns keys.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
typedef struct MDNSKey{
   /**
    * @brief The label of the key
    */
   std::string name;

   /**
    * @brief The dns type value
    */
   uint16_t type;

   /**
    * The dns class (usually IN)
    */
   uint16_t _class;

   MDNSKey() : name(""), type(0), _class(0) {}
} mdns_key;

// utility functions:

/**
 * @brief Check whether the packet is a probe.
 *
 * @param p @ref DNSPacket that needs to be checked.
 * @return 1 if true, 0 otherwise.
 */
int isProbe(DNSPacket* p);

/**
 * @brief Check whether the packet is an announcment.
 *
 * @param p @ref DNSPacket that needs to be checked.
 * @return 1 if true, 0 otherwise.
 */
int isAnnouncement(DNSPacket* p);

/**
 * @brief Check whether the packet is a query.
 *
 * @param p @ref DNSPacket that needs to be checked.
 * @return 1 if true, 0 otherwise.
 */
int isQuery(DNSPacket* p);

/**
 * @brief Check whether the packet is a response.
 *
 * @param p @ref DNSPacket that needs to be checked.
 * @return 1 if true, 0 otherwise.
 */
int isResponse(DNSPacket* p);

/**
 * @brief Check whether the packet is a goodbye record.
 *
 * @param p @ref DNSPacket that needs to be checked.
 * @return 1 if true, 0 otherwise.
 */
int isGoodbye(std::shared_ptr<DNSRecord> r);

/**
 * @brief Compare two mdns keys
 *
 * @param key1 @ref MDNSKey first key to check
 * @param key2 @ref MDNSKey second key to check
 * @return -1 if key2 > key 1, 0 if key1 == key2 and 1 if key1 > key2.
 */
int compareMDNSKey(std::shared_ptr<ODnsExtension::MDNSKey> key1, std::shared_ptr<ODnsExtension::MDNSKey> key2);

/**
 * @brief Compare two mdns keys
 *
 * Without comparing their types.
 *
 * @param key1 @ref MDNSKey first key to check
 * @param key2 @ref MDNSKey second key to check
 * @return -1 if key2 > key 1, 0 if key1 == key2 and 1 if key1 > key2.
 */
int compareMDNSKeyANY(std::shared_ptr<ODnsExtension::MDNSKey> key1, std::shared_ptr<ODnsExtension::MDNSKey> key2);

/**
 * @brief Create a new @ref MDNSKey
 *
 * @param name the name of the key
 * @param type the dns type of the key
 * @param _class the dns class of the key
 *
 * @return Smart pointer to the newly created @ref MDNSKey
 */
std::shared_ptr<MDNSKey> mdns_key_new(std::string name, int type, int _class);

/**
 * @brief Free a given @ref MDNSKey
 *
 * The smart pointer is reset, which will cause the key to be destructed.
 *
 * @param key The @ref MDNSKey that needs to be freed.
 */
void mdns_key_free(std::shared_ptr<MDNSKey> key);

/**
 * @brief Helper method to create a @ref DNSQuestion
 *
 * @param name the query name/label
 * @param type the dns type for the question
 * @param _class the dns class for the question
 *
 * @return Smart pointer to the newly created @ref DNSQuestion
 */
std::shared_ptr<DNSQuestion> createQuestion(std::string name, unsigned short type, unsigned short _class);

/**
 * @brief Helper method to create a @ref DNSQuestion
 *
 * @param key @ref MDNSKey from which the question should be created.
 *
 * @return Smart pointer to the newly created @ref DNSQuestion
 */
std::shared_ptr<DNSQuestion> createQuestionFromKey(std::shared_ptr<MDNSKey> key);

#define MAX_MDNS_PACKET_SIZE 8000 // leaving plenty of room for UDP + IP + ETHERNET, since max size is 9000
#define MDNS_PORT 5353
#define MDNS_HOST_TTL 120
#define MDNS_SERVICE_TTL 60*75

}

#endif /* MDNS_H_ */
