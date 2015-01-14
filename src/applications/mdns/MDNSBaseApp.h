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

#ifndef __OPP_DNS_EXTENSION_MDNSBASEAPP_H_
#define __OPP_DNS_EXTENSION_MDNSBASEAPP_H_

#include <omnetpp.h>
#include "DNS.h"
#include "DNSTools.h"
#include "MDNS.h"
#include <glib.h>

/**
 * @brief MDNSBaseApp
 *  This app provides functionalities of typical mDNS-SD daemons like
 *  avahi or bonjour. Parametrized services can be announced and configured
 *  to create traffic based on a certain traffic model.
 */
class MDNSBaseApp : public cSimpleModule
{
  protected:
    virtual void initialize();
    virtual void handleMessage(cMessage *msg);

    /**
     * @brief handleServiceTraffic
     *  This method generates traffic for a certain service based on
     *  a given traffic model. Status changes in some programs, lead
     *  to announcements in the network.
     */
    virtual void handleServiceTraffic();

    /**
     * @brief publishService
     *  Publishes a service in the multicast network.
     * @params
     *      srv - instance of a service structure that should be published
     *
     */
    virtual void publishService(MDNSService *srv);

    /**
     * @brief resolve
     *  Resolves an MDNS query
     * @params
     *      query - DNSPacket containing the query
     */
    virtual void resolve(DNSPacket* query);

    /**
     * @brief handleAnnouncement
     *  Handle DNSPackets containing service announcments from other
     *  users in the network.
     *
     * @params
     *      query - DNSPacket containing the query
     */
    virtual void handleAnnouncement(DNSPacket* query);

    /**
     * @brief handleResponse
     *  Handles responses to questions that this client may have sent.
     *
     * @params
     *      query - DNSPacket containing the query
     */
    virtual void handleResponse(DNSPacket* query);

    /**
     * @brief handleQuestion
     *  Handles questions sent into the network by other users.
     *
     * @params
     *      query - DNSPacket containing the query
     */
    virtual void handleQuestion(DNSPacket* query);

};

#endif
