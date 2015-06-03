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
#include <memory>

namespace INETDNS {

/**
 * @brief Observer interface for timeevents.
 *
 * A class utilizing the time event set can get notified
 * if any changes are made not performed by itself.
 */
class TimeEventSetObserver {
public:
    virtual void notify() = 0;
};

/**
 * @brief Holds all information necessary for time event scheduling.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class TimeEvent {
protected:
    /**
     * @brief The time the event expires.
     */
    simtime_t expiry;

    /**
     * @brief The time the callback was last performed.
     */
    simtime_t last_run;

    /**
     * @brief Data, usually a job that has to be performed
     */
    std::shared_ptr<void> data;

    /**
     * @brief Pointer to the object that scheduled this event.
     */
    void* scheduler;

    /**
     * @brief callback function, to call the correct scheduler to perform the job.
     */
    void (*callback)(INETDNS::TimeEvent*, std::shared_ptr<void>, void*);

public:
    /**
     * @brief Constructor for time events.
     *
     * @param _scheduler The pointer to the object that scheduled
     * the event and wants to perform some operation using the callback.
     */
    TimeEvent(void* _scheduler) {
        scheduler = _scheduler;
    }

    virtual ~TimeEvent() {

    }

    /**
     * @return Smart pointer to the data coming with this event.
     */
    std::shared_ptr<void> getData() {
        return data;
    }

    /**
     * @param _data Smart pointer to the data coming with this event.
     */
    void setData(std::shared_ptr<void> _data) {
        data = _data;
    }

    /**
     * @brief performs the callback on the object that scheduled this event.
     */
    void performCallback() {
        callback(this, data, scheduler);
    }

    /**
     * @brief Static callback reference
     */
    void setCallback(
            void (_callback)(INETDNS::TimeEvent*, std::shared_ptr<void>,
                    void*)) {
        callback = _callback;
    }

    /**
     * @return the time this event was last run.
     */
    simtime_t getLastRun() {
        return last_run;
    }

    /**
     * @param _last_run the time this event was last run.
     */
    void setLastRun(simtime_t _last_run) {
        last_run = _last_run;
    }

    /**
     * @return the time this event expires.
     */
    simtime_t getExpiry() {
        return expiry;
    }

    /**
     * @param _expiry the time this event expires.
     */
    void setExpiry(simtime_t _expiry) {
        expiry = _expiry;
    }

};

/**
 * @brief A comparator for time events.
 *
 * This comparator can be used within standard library containers.
 * The @ref TimeEvent that has the earlier expiry is considered "smaller".
 *
 * If the expiries are equal, the event with the older last run
 * is considered "greater".
 *
 * Otherwise they are equal.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class TimeEventComparator {
public:
    TimeEventComparator() {

    }
    virtual ~TimeEventComparator() {

    }

    bool operator()(INETDNS::TimeEvent* t1,
            INETDNS::TimeEvent* t2) {
        // t1 < t2,
        // meaning t1s time is up before t2s
        if (t1->getExpiry() != t2->getExpiry())
            return t1->getExpiry() < t2->getExpiry();
        if (t1->getLastRun() != t2->getLastRun())
            return t1->getLastRun() < t2->getLastRun();
        if (t1->getData() != t2->getData())
            return 1;

        return 0;
    }
};

/**
 * @brief Encapsulates a standard library set.
 *
 * Since the set is ordered, the TimeEvents can be ordered
 * by age.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 *
 */
class TimeEventSet {
protected:
    /**
     * @brief Set used for ordering time events.
     */
    std::set<INETDNS::TimeEvent*, INETDNS::TimeEventComparator> timeEventSet;

    /**
     * @brief List of observers being notified on changes.
     */
    std::vector<INETDNS::TimeEventSetObserver*> observers;

public:
    TimeEventSet();
    virtual ~TimeEventSet();

    /**
     * @brief Adds a time event to the set
     *
     * @param t The time event to be added.
     */
    void addTimeEvent(INETDNS::TimeEvent* t);

    /**
     * @brief Updates a time event in the set
     *
     * @param t The time event to be updatet.
     * @param expiry The new expiry of the time event.
     */
    void updateTimeEvent(INETDNS::TimeEvent* t, simtime_t expiry);

    /**
     * @brief Removes a time event from the set
     *
     * @param t The time event to be removed.
     */
    void removeTimeEvent(INETDNS::TimeEvent* t);

    /**
     * @return The next due time event, if expiry has passed.
     */
    INETDNS::TimeEvent* getTimeEventIfDue();

    /**
     * @return The time event, with oldest age of expiry.
     */
    INETDNS::TimeEvent* getTopElement();

    void attach(INETDNS::TimeEventSetObserver* observer) {
        observers.push_back(observer);
    }

    void notify() {
        for (auto observer : observers) {
            observer->notify();
        }
    }
};

} /* namespace ODnsExtension */

#endif /* TIMEEVENTSET_H_ */
