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

#include "GenericTraffGen.h"

Define_Module(GenericTraffGen);

void GenericTraffGen::initialize(int stage)
{
    if (stage == inet::INITSTAGE_APPLICATION_LAYER) // initialize after network configuration has been done..
    {
        // First initialize ned parameters
        minApps = (int) par("minApps").doubleValue();
        maxApps = (int) par("maxApps").doubleValue();
        minBps = (int) par("minBps").doubleValue();
        maxBps = (int) par("maxBps").doubleValue();
        appInterArrivalMean = (int) par("appInterArrivalMean").doubleValue();
        appServiceTimeMean = (int) par("appServiceTimeMean").doubleValue();

        hasCBR = par("hasCBR").boolValue();
        hasBURST = par("hasBURST").boolValue();
        hasLRD = par("hasLRD").boolValue();

        lrdParetoAlpha = par("lrdParetoAlpha").doubleValue();
        lrdParetoBeta = par("lrdParetoBeta").doubleValue();

        dynamicApps = par("dynamicApps").boolValue();

        udpStandardPort = (int) par("udpStandardPort").doubleValue();
        udpOut.setOutputGate(gate("udpAppOut"));
        udpOut.bind(udpStandardPort);
        udpOut.setTimeToLive(15);

        const char* sinkModule = par("sink");
        inet::L3AddressResolver().tryResolve(sinkModule, sink);

        int initialApps = intuniform(minApps, maxApps);
        // create apps, push them into the vector
        int startup = 0;

        // Generate Traffic type choices.
        int ttypes = 0;
        std::vector<TRAFFIC_TYPE> choices;
        if(hasCBR) {
            choices.push_back(TRAFFIC_TYPE::CBR);
            ttypes++;
        }
        if(hasBURST) {
            choices.push_back(TRAFFIC_TYPE::BURST);
            ttypes++;
        }
        if(hasLRD) {
            choices.push_back(TRAFFIC_TYPE::LRD);
            ttypes++;
        }

        for (int i = 0; i < initialApps; i++)
        {
            // using triangular distribution for bandwidth with mean
            // in the middle of minBps and maxBps
            int bps = (int) triang(minBps, (minBps + maxBps) / 2, maxBps);

            // choose a traffic type for the app
            int choice = intuniform(0, ttypes - 1);

            std::shared_ptr<TrafficApp> app = TrafficAppFactory().create(choices[choice], bps);
            if(choices[choice] == TRAFFIC_TYPE::LRD)
                std::static_pointer_cast<TrafficAppLRD>(app)->setLRDParam(lrdParetoAlpha, lrdParetoBeta);
            apps.push_back(app);

            // schedule startup some time in the future...
            cMessage* selfMessage = new cMessage("timer");
            selfMessage->addPar("vectorPos");
            selfMessage->par("vectorPos") = i;
            selfMessage->setKind(TRAFF_APP_TIMER);

            // pick time to start app using Poisson distribution
            startup += (int) exponential((double) appInterArrivalMean);
            int serviceTime = (int) exponential((double) appServiceTimeMean);

            std::string startupStr = std::to_string(startup) + std::string("s");
            simtime_t time = simTime() + STR_SIMTIME(startupStr.c_str());
            app->firstTimer = time;

            std::string serviceTimeStr = std::to_string(serviceTime) + std::string("s");
            app->serviceTime = time + STR_SIMTIME(serviceTimeStr.c_str());

            EV << "Starting app at: " << startupStr << "/" << serviceTimeStr << " with BPS: " << bps << "\n";

            scheduleAt(time, selfMessage);
        }
    }

}

void GenericTraffGen::handleMessage(cMessage *msg)
{
    if(msg->getKind() == TRAFF_APP_TIMER){
        int vectorPos = msg->par("vectorPos");
        std::shared_ptr<TrafficApp> app = apps[vectorPos];

        TrafficChunk chunk = app->getNextTrafficChunk();
        // schedule next msg..
        if(simTime() < app->serviceTime){
            scheduleAt(chunk.nextTimer, msg);
        }

        // use chunk to send out traffic..
        if(chunk.payloadSize != -1){
            if(chunk.payloadSize < 65507){ // within range, otherwise send multiple packets, that amount to the same size.
                std::string msgname = std::string("tgen_pack::") + std::to_string(vectorPos) + std::string("::") + std::to_string(app->getRunningId());
                cPacket* packet = new cPacket(msgname.c_str());
                packet->setByteLength(chunk.payloadSize);
                udpOut.sendTo(packet, sink, udpStandardPort);
            }
            else{
                int numPkts = chunk.payloadSize / 65507;
                int lastPkt = chunk.payloadSize - (65507 * numPkts);
                simtime_t intrvl = STR_SIMTIME("1s") / numPkts;

                // setup self message
                cMessage* nextChunk = new cMessage("nextChunk");
                nextChunk->setKind(TRAFF_APP_CHUNK_SPLIT);
                nextChunk->addPar("numPkts");
                nextChunk->addPar("lastPkt");
                nextChunk->addPar("intrvl");
                nextChunk->addPar("vectorPos");

                nextChunk->par("numPkts") = --numPkts;
                nextChunk->par("lastPkt") = lastPkt;
                nextChunk->par("vectorPos") = vectorPos;
                nextChunk->par("intrvl") = intrvl.dbl();

                scheduleAt(simTime() + intrvl, nextChunk);

                std::string msgname = std::string("tgen_pack::") + std::to_string(vectorPos) + std::string("::") + std::to_string(app->getRunningId()) + std::string("#") + std::to_string(numPkts);
                cPacket* packet = new cPacket(msgname.c_str());
                packet->setByteLength(65507);
                udpOut.sendTo(packet, sink, udpStandardPort);
            }
        }
    }
    else if(msg->getKind() == TRAFF_APP_CHUNK_SPLIT){
        int numPkts = (int) msg->par("numPkts").doubleValue();
        int lastPkt = (int) msg->par("lastPkt").doubleValue();
        int vectorPos = (int) msg->par("vectorPos").doubleValue();
        simtime_t intrvl = msg->par("intrvl").doubleValue();

        std::shared_ptr<TrafficApp> app = apps[vectorPos];

        numPkts--;
        if(numPkts == 0){
            std::string msgname = std::string("tgen_pack::") + std::to_string(vectorPos) + std::string("::") + std::to_string(app->getRunningId()) + std::string("#") + std::to_string(numPkts);
            cPacket* packet = new cPacket(msgname.c_str());
            packet->setByteLength(lastPkt);
            udpOut.sendTo(packet, sink, udpStandardPort);
            delete msg;
        }
        else{ // still packets to go..
            msg->par("numPkts") = numPkts;
            scheduleAt(simTime() + intrvl, msg);
            std::string msgname = std::string("tgen_pack::") + std::to_string(vectorPos) + std::string("::") + std::to_string(app->getRunningId()) + std::string("#") + std::to_string(numPkts);
            cPacket* packet = new cPacket(msgname.c_str());
            packet->setByteLength(65507);
            udpOut.sendTo(packet, sink, udpStandardPort);
        }
    }
}
