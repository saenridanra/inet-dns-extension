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

#include "MDNSResolver.h"

Define_Module(MDNSResolver);

MDNSResolver::MDNSResolver(){

}

MDNSResolver::~MDNSResolver(){
    // delete objects used in here..
    delete timeEventSet;
    delete probeScheduler;
    delete queryScheduler;
    delete responseScheduler;
}

void MDNSResolver::initialize()
{
    timeEventSet = new ODnsExtension::TimeEventSet();
    selfMessage = new cMessage("timer");
    selfMessage->setKind(MDNS_KIND_TIMER);
    scheduleAt(simTime()+elapseTime, selfMessage);

    probeScheduler = new ODnsExtension::MDNSProbeScheduler(timeEventSet);
    // TODO: Set cache of scheduler!
    queryScheduler = new ODnsExtension::MDNSQueryScheduler(timeEventSet);
    // TODO: Set cache of scheduler!
    responseScheduler = new ODnsExtension::MDNSResponseScheduler(timeEventSet);
    // TODO: Set cache of scheduler!

    cache = new ODnsExtension::DNSTTLCache();
}

void MDNSResolver::handleMessage(cMessage *msg)
{
    if(msg->isSelfMessage()){
        if(msg->getKind() == MDNS_KIND_TIMER){
            elapsedTimeCheck();
            return;
        }
    }
    else{
        // check which kind it is
        if(msg->getKind() == MDNS_KIND_INTERNAL_QUERY){
            // this is a message from a module utilizing the mdns resolver
            // and wanting to perform a query..
            delete msg;
            return;
        }
        else if(msg->getKind() == MDNS_KIND_EXTERNAL){
            DNSPacket* p = check_and_cast<DNSPacket*>(msg);
            if(ODnsExtension::isQuery(p)){
                handleQuery(p);
                delete msg;
                return;
            }
            else if(ODnsExtension::isResponse(p)){
                handleResponse(p);
                delete msg;
                return;
            }
            else if(ODnsExtension::isProbe(p)){
                handleProbe(p);
                delete msg;
                return;
            }
            else if(ODnsExtension::isAnnouncement(p)){
                handleAnnouncement(p);
                delete msg;
                return;
            }

            // something went wrong, message unknown.
            delete msg;
            return;
        }
    }
}

void MDNSResolver::elapsedTimeCheck(){
    // first, schedule new elapseTimeCheck
    scheduleAt(simTime()+elapseTime, selfMessage);

    // perform a cache cleanup, every entry that has passed
    // it's TTL was not successfully updated
    cache->cleanup();

    // check if we have an event coming up now, i.e. check if we can get
    // an event from the timeEventSet
    ODnsExtension::TimeEvent* event;
    if((event = timeEventSet->getTimeEventIfDue())){
        // perform the timeEvent..
        event->performCallback(); // the rest is handled in the callback
    }

}

void MDNSResolver::handleProbe(DNSPacket* p){

}

void MDNSResolver::handleQuery(DNSPacket* p){

}

void MDNSResolver::handleAnnouncement(DNSPacket* p){

}

void MDNSResolver::handleResponse(DNSPacket* p){

}
