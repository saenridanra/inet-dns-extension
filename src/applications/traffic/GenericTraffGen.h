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

#ifndef __INETDNS_GENERICTRAFFGEN_H_
#define __INETDNS_GENERICTRAFFGEN_H_

#include <omnetpp.h>

#include <TCPSocket.h>
#include <UDPSocket.h>

#include <IPvXAddress.h>
#include <IPvXAddressResolver.h>

#include <memory>
#include <vector>
#include <string.h>

#define TRAFF_APP_TIMER 0

/**
 * @brief Enumeration for the different Protocols.
 */
enum PROTO
{
    TCP, UDP
};

enum TRAFFIC_TYPE
{
    CBR, BURST
};

class TrafficChunk
{
    public:
        /**
         * @brief The next time event the app should generate traffic.
         */
        simtime_t nextTimer;

        /**
         * Payload size in bytes.
         */
        int payloadSize;

        /**
         * The protocol to be used.
         */
        PROTO P;
};

/**
 * @brief An app that generates traffic, based on parameters.
 */
class TrafficApp
{
    protected:
        PROTO P;
        TRAFFIC_TYPE T;
        int BPS;

    public:
        /**
         * @brief Constructs a @brief TrafficApp.
         *
         * @param p @ref PROTO determining the protocol this app uses.
         * @param t @ref TRAFFIC_TYPE determining the type of traffic that is generated.
         * @param bps Bandwidth this app consumes (bits per second).
         */
        TrafficApp(PROTO p, TRAFFIC_TYPE t, int bps)
        {
            P = p;
            T = t;
            BPS = bps;
        }
        ;
        ~TrafficApp(){};

        /**
         * @brief Generates a chunk of traffic based on parameters.
         *
         * @return A @ref TrafficChunk object.
         */
        TrafficChunk getNextTrafficChunk()
        {
            switch (T)
            {
                case CBR:
                    return getCBR();
                case BURST:
                    return getBURST();
                default:
                    throw new cRuntimeError("Traffic type not specified in traffic app.");
            }
        }
        ;
    protected:
        TrafficChunk getCBR()
        {
            TrafficChunk chunk;
            chunk.P = this->P;
            chunk.nextTimer = simTime() + STR_SIMTIME("1s"); // schedule equal chunks every second..
            chunk.payloadSize = BPS / 8;
            return chunk;
        }
        ;
        TrafficChunk getBURST()
        {
            // pick time delay
            int delay = intuniform(1, 120);
            std::string delayToStr = std::to_string(delay) + std::string("s");
            TrafficChunk chunk;
            chunk.P = this->P;
            chunk.nextTimer = simTime() + STR_SIMTIME(delayToStr.c_str());
            chunk.payloadSize = (BPS * delay) / 8; // we achieve bps by considering the delay
            return chunk;
        }
        ;
};

/**
 * @brief UDP and TCP based Traffic generator
 *
 * Based on network flows with different properties.
 */
class GenericTraffGen : public cSimpleModule
{
    protected:
        /**
         * @brief Sink identifier.
         *
         * This is the identifier for the sink, this traffic generator
         * sends data to.
         */
        IPvXAddress sink;

        /**
         * @brief Apps that generate traffic.
         */
        std::vector<std::shared_ptr<TrafficApp>> apps;

        /**
         * @brief Sockets this generator uses.
         */
        UDPSocket udpOut;
        TCPSocket tcpOut;

        int udpStandardPort;
        int tcpStandardPort;

        /**
         * @brief Parameters for the traffic generator.
         */
        int minApps, maxApps, minBps, maxBps;
        bool hasUDP, hasTCP, hasCBR, hasBURST, dynamicApps;

    protected:
        virtual void initialize(int stage);
        virtual int numInitStages() const
        {
            return 4;
        }
        virtual void handleMessage(cMessage *msg);
};

#endif
