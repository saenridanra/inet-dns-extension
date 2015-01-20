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

#include <mdns/MDNSProbeScheduler.h>

namespace ODnsExtension {

MDNSProbeScheduler::MDNSProbeScheduler(ODnsExtension::TimeEventSet* _timeEventSet)
{
    timeEventSet = _timeEventSet;
}

MDNSProbeScheduler::~MDNSProbeScheduler()
{
    // TODO Auto-generated destructor stub
}


ODnsExtension::MDNSProbeJob* MDNSProbeScheduler::new_job(ODnsExtension::DNSRecord* r){

}

ODnsExtension::MDNSProbeJob* MDNSProbeScheduler::find_job(ODnsExtension::DNSRecord* r){

}

ODnsExtension::MDNSProbeJob* MDNSProbeScheduler::find_history(ODnsExtension::DNSRecord* r){

}

void MDNSProbeScheduler::done(ODnsExtension::MDNSProbeJob* qj){

}

void MDNSProbeScheduler::remove_job(ODnsExtension::MDNSProbeJob* qj){

}

int MDNSProbeScheduler::preparePacketAndSend(GList* qlist, GList* anlist, GList* nslist, GList* arlist, int qdcount, int ancount, int nscount, int arcount, int packetSize, int TC){

}



void MDNSProbeScheduler::elapseCallback(ODnsExtension::TimeEvent* e, void* data, void* thispointer){
    MDNSProbeScheduler * self = static_cast<MDNSProbeScheduler*>(thispointer);
    self->elapse(e, data);
}

void MDNSProbeScheduler::post(ODnsExtension::MDNSKey* key, int immediately){

}

void MDNSProbeScheduler::elapse(ODnsExtension::TimeEvent* e, void* data){

}


} /* namespace ODnsExtension */
