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
#include <MDNSTrafficGenerator.h>

namespace ODnsExtension {

void MDNSTrafficGenerator::elapse(ODnsExtension::TimeEvent* e, std::shared_ptr<void> data)
{
    // post query
    int servicePick = intrand(serviceList.size() - 1);
    // create query
    std::shared_ptr<ODnsExtension::MDNSKey> key = ODnsExtension::mdns_key_new(serviceList[servicePick],
            DNS_TYPE_VALUE_ANY, DNS_CLASS_IN);
    queryScheduler->post(key, 0);

    // schedule next

    // set the first schedule for a query
    if (RUNNING == true)
    {
        simtime_t tv;
        // pick time of query from a normal distribution (but only positive values are considered)
        // stddev is 300, which makes it likely that within 5 minutes
        // a query is generated.
        int defer = (int) abs(normal(0, 300));
        // create simtime value from random deferral value
        std::string stime = std::to_string(defer) + std::string("s");
        tv = simTime() + STR_SIMTIME(stime.c_str());

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        std::shared_ptr<void> void_pointer = std::shared_ptr<void>(new int(0));
        e->setData(void_pointer);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSTrafficGenerator::elapseCallback);

        this->latestScheduledEvent = e;
    }
}

void MDNSTrafficGenerator::startQuerying()
{
    RUNNING = true;
    // set the first schedule for a query
    simtime_t tv;
    // pick time of query from a normal distribution (but only positive values are considered)
    // stddev is 300, which makes it likely that within 5 minutes
    // is sent...
    int defer = (int) abs(normal(0, 300));
    // create simtime value from random deferral value
    std::string stime = std::to_string(defer) + std::string("s");
    tv = simTime() + STR_SIMTIME(stime.c_str());

    ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
    std::shared_ptr<void> void_pointer = std::shared_ptr<void>(new int(0));
    e->setData(void_pointer);
    e->setExpiry(tv);
    e->setLastRun(0);
    e->setCallback(ODnsExtension::MDNSTrafficGenerator::elapseCallback);

    this->latestScheduledEvent = e;

    timeEventSet->addTimeEvent(e);
}

void MDNSTrafficGenerator::stopQuerying()
{
    RUNNING = false;
}

} /* namespace ODnsExtension */
