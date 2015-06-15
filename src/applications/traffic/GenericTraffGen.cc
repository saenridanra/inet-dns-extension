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
    if (stage == 3) // initialize after network configuration has been done..
    {
        // First initialize ned parameters
        minApps = (int) par("minApps").doubleValue();
        maxApps = (int) par("maxApps").doubleValue();
        minBps = (int) par("minBps").doubleValue();
        maxBps = (int) par("maxBps").doubleValue();

        hasCBR = par("hasCBR").boolValue();
        hasBURST = par("hasBURST").boolValue();
        dynamicApps = par("dynamicApps").boolValue();

        udpStandardPort = (int) par("udpStandardPort").doubleValue();
        udpOut.setOutputGate(gate("udpAppOut"));
        udpOut.bind(udpStandardPort);
        udpOut.setTimeToLive(15);

        const char* sinkModule = par("sink");
        IPvXAddressResolver().tryResolve(sinkModule, sink);

        int initialApps = intuniform(minApps, maxApps);
        // create apps, push them into the vector
        for (int i = 0; i < initialApps; i++)
        {
            int bps = intuniform(minBps, maxBps);
            TRAFFIC_TYPE t;

            if (hasCBR && hasBURST)
            {
                int choice = intuniform(0, 1);
                if (choice)
                    t = CBR;
                else
                    t = BURST;
            }
            else if (hasCBR)
                t = CBR;
            else if (hasBURST)
                t = BURST;
            else
                throw new cRuntimeError("No traffic type specified for traffic generator.");

            std::shared_ptr<TrafficApp> app = std::shared_ptr < TrafficApp > (new TrafficApp(t, bps));
            apps.push_back(app);

            // schedule startup some time in the future...

            cMessage* selfMessage = new cMessage("timer");
            selfMessage->addPar("vectorPos");
            selfMessage->par("vectorPos") = i;
            selfMessage->setKind(TRAFF_APP_TIMER);

            // pick time to star app
            int startup = intuniform(10, 600); // after 10 to 600s..
            std::string startupStr = std::to_string(startup) + std::string("s");
            simtime_t time = simTime() + STR_SIMTIME(startupStr.c_str());

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
        scheduleAt(chunk.nextTimer, msg);

        // use chunk to send out traffic..
        std::string msgname = std::string("tgen_pack::") + std::to_string(vectorPos);
        cPacket* packet = new cPacket(msgname.c_str());
        packet->setByteLength(chunk.payloadSize);
        udpOut.sendTo(packet, sink, udpStandardPort);
    }
}
