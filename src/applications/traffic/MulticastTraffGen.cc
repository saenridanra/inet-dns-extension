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

#include "MulticastTraffGen.h"

Define_Module(MulticastTraffGen);

void MulticastTraffGen::initialize(int stage)
{
    if(stage == inet::INITSTAGE_APPLICATION_LAYER){
        // initialize multicast group address we send data to
        std::string multicastGroupString = par("multicastGroups").stdstringValue();
        std::vector<std::string> groupAddresses = cStringTokenizer(multicastGroupString.c_str()).asVector();
        for(auto a : groupAddresses){
            inet::L3Address address = inet::L3AddressResolver().resolve(multicastGroupString.c_str());
            multicastGroups.push_back(address);
        }

        byterate = (int) par("byterate").doubleValue();
        std::string trafficType = par("MulticastTrafficType").stdstringValue();
        if(trafficType == "Simple"){
            mcastTrafficType = MULTICAST_TRAFFIC_TYPE::Simple;
        }
        else if(trafficType == "Streaming"){
            mcastTrafficType = MULTICAST_TRAFFIC_TYPE::Streaming;
        }
        else{
            throw cRuntimeError("No valid traffic type has been specified.");
        }

        outSock.setOutputGate(gate("udpAppOut"));
        outSock.bind(MulticastTraffGenPort);
        outSock.setTimeToLive(15);

        inet::MulticastGroupList mgl = inet::getModuleFromPar<inet::IInterfaceTable>(par("interfaceTableModule"), this)->collectMulticastGroups();
        outSock.joinLocalMulticastGroups(mgl);

        // initialize first ON period.
        // draw from Poisson distribution, since a user initiated
        // session is modeled in this case.
        generateNewServiceTimes();

        timer = new cMessage("timer");
        timer->setKind(TIMER_KIND_START);

        scheduleAt(startTime, timer);
    }
}

void MulticastTraffGen::generateNewServiceTimes(){
    int startup = (int) exponential((double) 5);
    int serviceTime = 0;

    if(mcastTrafficType == MULTICAST_TRAFFIC_TYPE::Streaming){
        // assume an audio file needs to be send, which is approx. 5MB.
        // we divide the file by our byterate and obtain the service time
        // needed to send the file.
        lastFileSize = 1000000 * intuniform(3, 10);
        serviceTime = lastFileSize / byterate;
    }
    else if(mcastTrafficType == MULTICAST_TRAFFIC_TYPE::Simple){
        // draw the service time from the poisson distribution as well
        serviceTime = (int) exponential((double) 10);
    }

    int end = startup + serviceTime;

    std::string strstart = std::to_string(startup) + "s";
    startTime = simTime() + STR_SIMTIME(strstart.c_str());

    std::string strend = std::to_string(end) + "s";
    startTime = simTime() + STR_SIMTIME(strend.c_str());
}

void MulticastTraffGen::sendData(int time){
    if(mcastTrafficType == MULTICAST_TRAFFIC_TYPE::Simple){
        // send burst, based on last time data was sent.

        // determine delay for burst.
        lastDataSent = simTime();

        // send burst in relation to timeout
        // thus bitrate * burst
        int dataToSend = time * byterate;

        if(dataToSend < 65507){
            std::string msgname = std::string("mgen_pack::") + std::to_string(packetCount);
            cPacket* packet = new cPacket(msgname.c_str());
            packet->setByteLength(dataToSend);
            packet->addPar("packetID");
            packet->par("packetID") = packetCount;
            for(auto a : multicastGroups)
                outSock.sendTo(packet->dup(), a, MulticastTraffGenPort); // just use some port..
            delete packet;
        }
        else{
            // need to split..
            int numPkts = dataToSend / 65507;
            int lastPkt = dataToSend - (65507 * numPkts);
            simtime_t intrvl = STR_SIMTIME("1s") / numPkts;

            // setup self message
            cMessage* nextChunk = new cMessage("nextChunk");
            nextChunk->setKind(TRAFF_APP_CHUNK_SPLIT);
            nextChunk->addPar("numPkts");
            nextChunk->addPar("lastPkt");
            nextChunk->addPar("intrvl");
            nextChunk->addPar("packetID");

            nextChunk->par("numPkts") = --numPkts;
            nextChunk->par("lastPkt") = lastPkt;
            nextChunk->par("intrvl") = intrvl.dbl();
            nextChunk->par("packetID") = packetCount;

            scheduleAt(simTime() + intrvl, nextChunk);

            std::string msgname = std::string("mgen_pack::") + std::to_string(packetCount) + std::string("#") + std::to_string(numPkts);
            cPacket* packet = new cPacket(msgname.c_str());
            packet->setByteLength(65507);
            packet->addPar("packetID");
            packet->par("packetID") = packetCount;
            for(auto a : multicastGroups)
                outSock.sendTo(packet->dup(), a, MulticastTraffGenPort); // just use some port..
            delete packet;
        }
        packetCount++;

    }
    else if(mcastTrafficType == MULTICAST_TRAFFIC_TYPE::Streaming){
        if(byterate < 65507){
            std::string msgname = std::string("mgen_pack::") + std::to_string(packetCount);
            cPacket* packet = new cPacket(msgname.c_str());
            packet->setByteLength(byterate);
            packet->addPar("packetID");
            packet->par("packetID") = packetCount;
            for(auto a : multicastGroups)
                outSock.sendTo(packet->dup(), a, MulticastTraffGenPort); // just use some port..
            delete packet;
        }
        else{
            // need to split..
            int numPkts = byterate / 65507;
            int lastPkt = byterate - (65507 * numPkts);
            simtime_t intrvl = STR_SIMTIME("1s") / numPkts;

            // setup self message
            cMessage* nextChunk = new cMessage("nextChunk");
            nextChunk->setKind(TRAFF_APP_CHUNK_SPLIT);
            nextChunk->addPar("numPkts");
            nextChunk->addPar("lastPkt");
            nextChunk->addPar("intrvl");
            nextChunk->addPar("packetID");

            nextChunk->par("numPkts") = --numPkts;
            nextChunk->par("lastPkt") = lastPkt;
            nextChunk->par("intrvl") = intrvl.dbl();
            nextChunk->par("packetID") = packetCount;

            scheduleAt(simTime() + intrvl, nextChunk);

            std::string msgname = std::string("mgen_pack::") + std::to_string(packetCount) + std::string("#") + std::to_string(numPkts);
            cPacket* packet = new cPacket(msgname.c_str());
            packet->addPar("packetID");
            packet->par("packetID") = packetCount;
            packet->setByteLength(65507);
            for(auto a : multicastGroups)
                outSock.sendTo(packet->dup(), a, MulticastTraffGenPort); // just use some port..
            delete packet;
        }
        packetCount++;
    }

}

bool MulticastTraffGen::sendSplit(cMessage *msg){
    int numPkts = (int) msg->par("numPkts").doubleValue();
    int lastPkt = (int) msg->par("lastPkt").doubleValue();
    int packetID = (int) msg->par("packetID").doubleValue();
    simtime_t intrvl = msg->par("intrvl").doubleValue();

    numPkts--;
    std::cout << "Sending packet: " << numPkts << std::endl;
    std::string msgname = std::string("mgen_pack::") + std::to_string(packetID) + std::string("#") + std::to_string(numPkts);
    cPacket* packet = new cPacket(msgname.c_str());
    if(numPkts == 0){
        packet->setByteLength(lastPkt);
    }
    else{
        msg->par("numPkts") = numPkts;
        scheduleAt(simTime() + intrvl, msg);
        packet->setByteLength(65507);
    }
    for(auto a : multicastGroups)
        outSock.sendTo(packet->dup(), a, MulticastTraffGenPort); // just use some port..
    delete packet;

    return (bool) numPkts == 0;
}

void MulticastTraffGen::handleMessage(cMessage *msg)
{
    if(msg->isSelfMessage()){
        int burst = (int) exponential((double) 5);
        switch(msg->getKind()){
        case TIMER_KIND_START:
            timer->setKind(TIMER_KIND_RUNNING);
        case TIMER_KIND_RUNNING:
            // While running data is sent, next selfMessage is scheduled.
            sendData(burst);
            // check if the service time ends.
            if(simTime() > endTime){
                // schedule next timer using sleep message
                timer->setKind(TIMER_KIND_SLEEP);
                // determine the sleep period.
                int sleepintrvl = (int) exponential((double) 5);
                std::string strsleep = std::to_string(sleepintrvl) + std::string("s");
                simtime_t sleepTime = simTime() + STR_SIMTIME(strsleep.c_str());

                scheduleAt(sleepTime, timer);
            }
            else{
                if(mcastTrafficType == MULTICAST_TRAFFIC_TYPE::Simple){
                    std::string strburst = std::to_string(burst) + std::string("s");
                    simtime_t burstTime = simTime() + STR_SIMTIME(strburst.c_str());
                    scheduleAt(burstTime, timer);
                }
                else if(mcastTrafficType == MULTICAST_TRAFFIC_TYPE::Streaming){
                    scheduleAt(simTime() + STR_SIMTIME("1s"), timer);
                }
            }
            break;
        case TIMER_KIND_SLEEP:
            // determine new phase:
            generateNewServiceTimes();

            timer = new cMessage("timer");
            timer->setKind(TIMER_KIND_START);

            scheduleAt(startTime, timer);
            break;
        case TRAFF_APP_CHUNK_SPLIT:
            if(sendSplit(msg)){
                delete msg;
            }
            break;
        default: break;
        }
    }
}

void MulticastTraffGen::finish(){

}
