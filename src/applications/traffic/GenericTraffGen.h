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
#include "INETDefs.h"
#include <TCPSocket.h>
#include <UDPSocket.h>

#include <L3AddressResolver.h>

#include <memory>
#include <vector>
#include <string.h>
#include <iostream>
#include <fstream>

#define TRAFF_APP_TIMER 16010
#define TRAFF_APP_CHUNK_SPLIT 16011
#define RECORD_THRUPUT 16012

enum TRAFFIC_TYPE
{
    CBR, BURST, LRD
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
};

/**
 * @brief An app that generates traffic, based on parameters.
 */
class TrafficApp
{
    public:
        simtime_t firstTimer = 0;
        simtime_t serviceTime = 0;
    protected:
        long runningId;
        int BPS;
        long lastPayloadSize;
        simtime_t last_timer;

    public:
        /**
         * @brief Constructs a @brief TrafficApp.
         *
         * @param t @ref TRAFFIC_TYPE determining the type of traffic that is generated.
         * @param bps Bandwidth this app consumes (bits per second).
         */
        TrafficApp(int bps)
        {
            runningId = 0;
            lastPayloadSize = -1;
            BPS = bps;
        };

        /**
         * @brief Generates a chunk of traffic based on parameters.
         *
         * @return A @ref TrafficChunk object.
         */
        virtual TrafficChunk getNextTrafficChunk() = 0;

        long getRunningId(){
            return runningId;
        };
};

class TrafficAppCBR : public TrafficApp{
public:
    TrafficAppCBR(int bps) : TrafficApp(bps){
    }
    TrafficChunk getNextTrafficChunk(){
        runningId++;
        TrafficChunk chunk;
        chunk.nextTimer = simTime() + STR_SIMTIME("1s"); // schedule equal chunks every second..
        chunk.payloadSize = BPS / 8;
        lastPayloadSize = chunk.payloadSize;
        last_timer = chunk.nextTimer;
        return chunk;
    }
};

class TrafficAppBurst : public TrafficApp{
public:
    TrafficAppBurst(int bps) : TrafficApp(bps){
    }
    TrafficChunk getNextTrafficChunk(){
        runningId++;
        // pick time delay
        int delay = intuniform(1, 120);
        std::string delayToStr = std::to_string(delay) + std::string("s");
        TrafficChunk chunk;
        chunk.nextTimer = simTime() + STR_SIMTIME(delayToStr.c_str());
        last_timer = chunk.nextTimer;
        chunk.payloadSize = (BPS * delay) / 8; // we achieve bps by considering the delay
        lastPayloadSize = chunk.payloadSize;
        return chunk;
    }
};

class TrafficAppLRD : public TrafficApp{
protected:
    simtime_t onPeriodStart;
    simtime_t onPeriodEnd;
    simtime_t offPeriodEnd;
    int currPayloadSize;
    double alpha, beta;

    void generatePayloadsForONPeriod(){
        // draw ON start and ON end from pareto distribution

        double startDbl = 60 * pareto_shifted(alpha, beta, 0);
        double endDbl = startDbl + 60 * pareto_shifted(alpha, beta, 0);
        double offEndDbl = endDbl + 60 * pareto_shifted(alpha, beta, 0);

        // scale to minutes..
        std::string start = std::to_string(startDbl) + std::string("s");
        std::string end = std::to_string(endDbl) + std::string("s");
        std::string offEnd = std::to_string(offEndDbl) + std::string("s");

        // generate period times
        onPeriodStart = simTime() + STR_SIMTIME(start.c_str());
        onPeriodEnd = simTime() + STR_SIMTIME(end.c_str());
        offPeriodEnd = simTime() + STR_SIMTIME(offEnd.c_str());

        double onDuration = endDbl - startDbl;
        double ovrlDuration = offEndDbl - startDbl;

        // Need to consider the OFF period as well and calculate payload size during ON
        // s.t. BPS is achieved over ON + OFF
        // Assume we send BPS per second, we can then scale this by dividing by: ON / (ON + OFF)
        currPayloadSize = BPS / (onDuration / ovrlDuration);
#ifdef DEBUG_ENABLED
        EV << "[TrafficAppLRD] **************************************************** \n";
        EV << "[TrafficAppLRD] ON Period Start: " << onPeriodStart << "\n";
        EV << "[TrafficAppLRD] ON Period End: " << onPeriodEnd << "\n";
        EV << "[TrafficAppLRD] Off Period End: " << offPeriodEnd << "\n";
        EV << "[TrafficAppLRD] Generated Pareto Sequence ON Duration: " << onDuration << "\n";
        EV << "[TrafficAppLRD] Generated Pareto Sequence ON/OFF Duration: " << ovrlDuration << "\n";
        EV << "[TrafficAppLRD] Using Payload Size: " << currPayloadSize << "\n";
        EV << "[TrafficAppLRD] **************************************************** \n";
#endif
    }

public:
    TrafficAppLRD(int bps) : TrafficApp(bps){
        // Add rngs, we use three for the different pareto distributions
        // to achieve independence
    }

    void setLRDParam(double alpha, double beta){
        this->alpha = alpha;
        this->beta  = beta;
    }

    TrafficChunk getNextTrafficChunk(){
        runningId++;
        /*
         * Modeling of self-similar traffic here:
         * We draw ON/Off periods from Pareto distributions and
         * send fixed rate traffic bursts during ON periods.
         */
        TrafficChunk chunk;
        if(lastPayloadSize == -1){
            // initialize ON period
            generatePayloadsForONPeriod();
        }

        if(simTime() + STR_SIMTIME(std::string("1s").c_str()) > onPeriodEnd){
            // start off period now
            chunk.nextTimer = offPeriodEnd;
            last_timer = chunk.nextTimer;
            chunk.payloadSize = currPayloadSize / 8; // we achieve bps by considering the delay
            lastPayloadSize = -1;
        }
        else{
            // generate next traffic chunk of currPayloadSize
            // check first if we already sent a payload.
            if(lastPayloadSize == -1){
                // if the simtime is smaller than the start of the ON period, we need to wait
                if(simTime() < onPeriodStart){
                    chunk.nextTimer = onPeriodStart;
                    last_timer = chunk.nextTimer;
                    chunk.payloadSize = -1; // signal that no packets needs to be sent
                    lastPayloadSize = 0; // don't generate the periods again
                }
                else{
                    // send the first packet
                    chunk.nextTimer = simTime() + STR_SIMTIME(std::string("1s").c_str());
                    last_timer = chunk.nextTimer;
                    chunk.payloadSize = currPayloadSize / 8; // we achieve bps by considering the delay
                    lastPayloadSize = chunk.payloadSize;
                }
            }
            else{
                chunk.nextTimer = simTime() + STR_SIMTIME(std::string("1s").c_str());
                last_timer = chunk.nextTimer;
                chunk.payloadSize = currPayloadSize / 8; // we achieve bps by considering the delay
                lastPayloadSize = chunk.payloadSize;
            }
        }
        return chunk;
    }
};

class TrafficAppFactory{
    public:
    std::shared_ptr<TrafficApp> create(TRAFFIC_TYPE t, int bps){
        if(t == TRAFFIC_TYPE::CBR) return std::shared_ptr<TrafficApp>(new TrafficAppCBR(bps));
        else if(t == TRAFFIC_TYPE::BURST) return std::shared_ptr<TrafficApp>(new TrafficAppBurst(bps));
        else if(t == TRAFFIC_TYPE::LRD) return std::shared_ptr<TrafficApp>(new TrafficAppLRD(bps));
        else{
            throw cRuntimeError("Error in creating an instance of traffic app of type: %s", t);
        }
    };
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
        inet::L3Address sink;

        /**
         * @brief Apps that generate traffic.
         */
        std::vector<std::shared_ptr<TrafficApp>> apps;

        /**
         * @brief Sockets this generator uses.
         */
        inet::UDPSocket udpOut;
        int udpStandardPort;

        /**
         * @brief Parameters for the traffic generator.
         */
        int minApps, maxApps, minBps, maxBps, appInterArrivalMean, appServiceTimeMean;
        double lrdParetoAlpha, lrdParetoBeta;
        bool hasCBR, hasBURST, hasLRD, dynamicApps, recordThruput;
        simtime_t recordThruputScale;
        std::string recordThruputFileColDelimiter;
        std::ofstream* recordThruputOutputStream;
        long bytesSent = 0;

    protected:
        virtual void initialize(int stage);
        virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
        virtual void handleMessage(cMessage *msg);
        virtual void finish() override;

        virtual void record();
};

#endif
