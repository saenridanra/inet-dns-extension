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


#ifndef __OPP_DNS_EXTENSION_MDNSRESOLVER_H_
#define __OPP_DNS_EXTENSION_MDNSRESOLVER_H_

#include <omnetpp.h>
#include <TimeEventSet.h>
#include <DNSCache.h>
#include <DNSTTLCache.h>
#include <DNSTools.h>
#include <DNS.h>
#include <MDNSProbeScheduler.h>
#include <MDNSResponseScheduler.h>
#include <MDNSQueryScheduler.h>


/**
 * @brief MDNSResolver
 *
 * Provides functionality of a mdns resolver. New queries
 * can be sent over the internal interface.
 *
 */
class MDNSResolver : public cSimpleModule
{
  protected:
    ODnsExtension::TimeEventSet* timeEventSet;
    ODnsExtension::MDNSProbeScheduler* probeScheduler;
    ODnsExtension::MDNSResponseScheduler* responseScheduler;
    ODnsExtension::MDNSQueryScheduler* queryScheduler;

    ODnsExtension::DNSTTLCache* cache;

    cMessage* selfMessage;

    simtime_t elapseTime = STR_SIMTIME("1ms"); // timer is set to 1ms, i.e. with a resolution of 1ms, elapsed times are checked.

  public:
    MDNSResolver();
    ~MDNSResolver();

  protected:
    virtual void initialize();
    virtual void handleMessage(cMessage *msg);

    virtual void elapsedTimeCheck();
    virtual void handleProbe(DNSPacket* p);
    virtual void handleQuery(DNSPacket* p);
    virtual void handleAnnouncement(DNSPacket* p);
    virtual void handleResponse(DNSPacket* p);
};

#define MDNS_KIND_TIMER 0
#define MDNS_KIND_EXTERNAL 1
#define MDNS_KIND_INTERNAL_QUERY 2

#endif
