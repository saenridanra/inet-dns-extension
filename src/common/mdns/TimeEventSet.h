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

#ifndef TIMEEVENTSET_H_
#define TIMEEVENTSET_H_

#include <omnetpp.h>
#include <iterator>
#include <set>

namespace ODnsExtension {

class TimeEvent{
    protected:
        simtime_t expiry;
        simtime_t last_run;

        // Data, usually a job that has to be performed
        void* data;
        // callback function, to call the correct scheduler
        // to perform the job.
        void* scheduler;
        void (*callback) (ODnsExtension::TimeEvent*, void*, void*);


    public:
        TimeEvent(void* _scheduler){
            scheduler = _scheduler;
        }

        virtual ~TimeEvent();

        void* getData(){
            return data;
        }

        void setData(void* _data){
            data = _data;
        }

        void performCallback(){
            callback(this, data, scheduler);
        }

        void setCallback(void (_callback) (ODnsExtension::TimeEvent*, void*, void*)){
            callback = _callback;
        }

        simtime_t getLastRun(){
            return last_run;
        }
        void setLastRun(simtime_t _last_run){
            last_run = _last_run;
        }

        simtime_t getExpiry(){
            return expiry;
        }
        void setExpiry(simtime_t _expiry){
            expiry = _expiry;
        }

};

class TimeEventComparator{
    public:
        TimeEventComparator();
        virtual ~TimeEventComparator();

        bool operator() (ODnsExtension::TimeEvent* t1, ODnsExtension::TimeEvent* t2){
            // t1 < t2,
            // meaning t1s time is up before t2s
            if(t1->getExpiry() != t2->getExpiry())
                return t1->getExpiry() < t2->getExpiry();

            return t1->getLastRun() < t2->getLastRun();
        }
};

/**
 * @brief TimeEventQueue
 *  Encapsulates a priority queue handling time events scheduled for the future.
 *
 */
class TimeEventSet
{
    protected:
        std::set<ODnsExtension::TimeEvent*, ODnsExtension::TimeEventComparator> timeEventSet;

    public:
        TimeEventSet();
        virtual ~TimeEventSet();

        void addTimeEvent(ODnsExtension::TimeEvent* t);
        void updateTimeEvent(ODnsExtension::TimeEvent* t, simtime_t expiry);
        void removeTimeEvent(ODnsExtension::TimeEvent* t);
        ODnsExtension::TimeEvent* getTimeEventIfDue();
};

} /* namespace ODnsExtension */

#endif /* TIMEEVENTSET_H_ */
