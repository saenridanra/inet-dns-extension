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

#include <mdns/TimeEventSet.h>

namespace ODnsExtension {

TimeEventSet::TimeEventSet()
{
    // nothing to do here
}

TimeEventSet::~TimeEventSet()
{
    // nothing to do, all values are on the stack

    std::set<ODnsExtension::TimeEvent*>::iterator iterator;
    for(iterator = timeEventSet.begin(); iterator != timeEventSet.end(); iterator++){
        delete *iterator;
    }

}

void TimeEventSet::addTimeEvent(ODnsExtension::TimeEvent* t)
{
    timeEventSet.insert(t);
}

void TimeEventSet::updateTimeEvent(ODnsExtension::TimeEvent* t, simtime_t expiry)
{
    // first erase it
    timeEventSet.erase(t);
    // set expiry
    t->setExpiry(expiry);
    // insert it again for resorting
    timeEventSet.insert(t);
}

void TimeEventSet::removeTimeEvent(ODnsExtension::TimeEvent* t)
{
    timeEventSet.erase(t);
}


ODnsExtension::TimeEvent* TimeEventSet::getTimeEventIfDue(){
    if(timeEventSet.empty()) return NULL;

    simtime_t now = simTime();
    ODnsExtension::TimeEvent* top = *timeEventSet.begin();
    if(top->getExpiry() <= now){
        // if another timevent is scheduled then it will
        // be readded by the scheduler accordingly so
        // it is at it's designated position. For now we
        // can remove it from the set.
        timeEventSet.erase(top);
        return top;
    }

    return NULL;
}

} /* namespace ODnsExtension */
