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

#ifndef __INET_DNS_EXTENSION_MULTICASTTRAFFGEN_H_
#define __INET_DNS_EXTENSION_MULTICASTTRAFFGEN_H_

#include <omnetpp.h>
#include "INETDefs.h"
#include "ModuleAccess.h"
#include <UDPSocket.h>
#include <L3Address.h>
#include <L3AddressResolver.h>

#include <vector>

#define TIMER_KIND_START 16020
#define TIMER_KIND_RUNNING 16021
#define TIMER_KIND_SLEEP 16022
#define TRAFF_APP_CHUNK_SPLIT 16023

enum MULTICAST_TRAFFIC_TYPE{
    Simple,
    Streaming
};

/**
 * This simple module generates mutlicast traffic (IP multicast).
 * The multicast group address needs to be specified
 * in the ned description file. There are three
 * types of multicast traffic data:
 *
 * - Simple data traffic (bursts at some points in time).
 * - Streaming data (continuous, i.e., CBR), bitrate needs to be specified.
 *
 * Note: One module corresponds to one traffic source.
 * You can add multiple modules to a compound module
 * in order to obtain multiple multicast traffic sources
 * per node. The data traffic is only unidirectional, i.e.
 * no responses are expected.
 */
class MulticastTraffGen : public cSimpleModule
{

  protected:
    /**
     * @brief Socket used to send mutlicast data.
     */
    inet::UDPSocket outSock;

    int MulticastTraffGenPort = 9000;

    /**
     * @brief Vector of addresses of multicast groups.
     */
    std::vector<inet::L3Address> multicastGroups;

    /**
     * @brief The byterate this modules has to send multicast data.
     */
    int byterate;

    /**
     * @brief Remember the file size, so we know how large the packets need to be.
     */
    int lastFileSize;

    /**
     * @brief Packets sent
     */
    long packetCount = 0;

    /**
     * @brief Remember when data was last sent (used for Simple method which send bursts).
     */
    simtime_t lastDataSent = -1;

    /**
     * @brief The multicast traffic type
     */
    MULTICAST_TRAFFIC_TYPE mcastTrafficType;

    /**
     * @brief Timer used to schedule packets.
     */
    cMessage* timer;

    simtime_t startTime;
    simtime_t endTime;

  public:
  protected:
    virtual void initialize(int stage);
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void handleMessage(cMessage *msg);
    virtual void finish() override;

    virtual void sendData(int time);
    virtual bool sendSplit(cMessage *msg);
    virtual void generateNewServiceTimes();
};

#endif
