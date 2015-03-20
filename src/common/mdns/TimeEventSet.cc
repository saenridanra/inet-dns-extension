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

#include <TimeEventSet.h>

namespace ODnsExtension {

TimeEventSet::TimeEventSet()
{
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
    // always add a small random delay to the timer,
    // so that we don't have "simultaneous" events .."
    int rand_delay = intrand(10); // delay of 10 ms
    char* stime = g_strdup_printf("%dms", rand_delay);
    t->setExpiry(t->getExpiry() + STR_SIMTIME(stime));
    g_free(stime);

    timeEventSet.insert(t);
}

void TimeEventSet::updateTimeEvent(ODnsExtension::TimeEvent* t, simtime_t expiry)
{
    // first erase it
    removeTimeEvent(t);
    // set expiry
    t->setExpiry(expiry);
    // insert it again for resorting
    timeEventSet.insert(t);
}

void TimeEventSet::removeTimeEvent(ODnsExtension::TimeEvent* t)
{
    std::set<ODnsExtension::TimeEvent*, ODnsExtension::TimeEventComparator>::iterator it;

    for(it = timeEventSet.begin(); it != timeEventSet.end(); it++){
        if(*it == t){
            timeEventSet.erase(it++);
            continue;
        }
    }
}

ODnsExtension::TimeEvent* TimeEventSet::getTopElement(){
    return *timeEventSet.begin();
}


ODnsExtension::TimeEvent* TimeEventSet::getTimeEventIfDue(){
    if(timeEventSet.empty()) return NULL;

    simtime_t now = simTime();
    std::set<ODnsExtension::TimeEvent*, ODnsExtension::TimeEventComparator>::iterator it = timeEventSet.begin();
    ODnsExtension::TimeEvent* top = *it;
    if(top->getExpiry() <= now){
        // if another timevent is scheduled then it will
        // be readded by the scheduler accordingly so
        // it is at it's designated position. For now we
        // can remove it from the set.
        timeEventSet.erase(it);
        return top;
    }

    return NULL;
}

} /* namespace ODnsExtension */
