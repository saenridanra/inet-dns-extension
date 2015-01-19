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

#include <mdns/MDNSQueryScheduler.h>

namespace ODnsExtension {

MDNSQueryScheduler::MDNSQueryScheduler(ODnsExtension::TimeEventSet* _timeEventSet)
{

    timeEventSet = _timeEventSet;
}

MDNSQueryScheduler::~MDNSQueryScheduler()
{
    // free all lists ...
}

void MDNSQueryScheduler::elapseCallback(ODnsExtension::TimeEvent* e, void* data, void* thispointer)
{
    MDNSQueryScheduler * self = static_cast<MDNSQueryScheduler*>(thispointer);
    self->elapse(e, data);
}

void MDNSQueryScheduler::elapse(ODnsExtension::TimeEvent* e, void* data)
{
    ODnsExtension::MDNSQueryJob* qj = (ODnsExtension::MDNSQueryJob*) data;

    if(qj->done){
        remove_job(qj); // remove the job from history as it is done already
        return;
    }

    DNSPacket* p;
    GList* knownAnswers; // append known answers from the cache in here

    GList* qlist;
    GList* anlist;
    GList* nslist;
    GList* arlist;

    int qdcount = 0;
    int ancount = 0;
    int nscount = 0;
    int arcount = 0;
    //char* msgname = g_strdup_printf("mdns_query#%d", id_count);
    //p = ODnsExtension::createNQuery(msgname, qj->key->name, qj->key->_class, qj->key->type, id, 0);

    qdcount++;
    ODnsExtension::DNSQuestion* q;
    q = createQuestionFromKey(qj->key);
    qlist = g_list_append(qlist, q);

    // append known answers for this query
    //append_cache_entries(key, knownAnswers);

}

ODnsExtension::MDNSQueryJob* MDNSQueryScheduler::find_job(ODnsExtension::MDNSKey* key)
{
    ODnsExtension::MDNSQueryJob* qj;
    GList* next = g_list_first(jobs);

    while (next)
    {
        qj = (ODnsExtension::MDNSQueryJob*) next->data;

        // check if they are the same
        int comp = ODnsExtension::compareMDNSKey(key, qj->key);
        if (!comp)
        {
            return qj;
        }

        next = g_list_next(next);
    }

    return NULL;

}

ODnsExtension::MDNSQueryJob* MDNSQueryScheduler::find_history(ODnsExtension::MDNSKey* key)
{
    ODnsExtension::MDNSQueryJob* qj;
    GList* next = g_list_first(history);

    while (next)
    {
        qj = (ODnsExtension::MDNSQueryJob*) next->data;

        // check if they are the same
        int comp = ODnsExtension::compareMDNSKey(key, qj->key);
        if (!comp)
        {
            return qj;
        }

        next = g_list_next(next);
    }

    return NULL;
}

void MDNSQueryScheduler::post(ODnsExtension::MDNSKey* key, int immediately)
{
    MDNSQueryJob* qj;
    simtime_t tv;

    if ((qj = find_history(key)))
        return;

    if (!immediately)
    {
        int defer = intrand(100) + 20;
        // create simtime value from random deferral value
        char* stime = g_strdup_printf("%dms", defer);
        tv = simTime() + STR_SIMTIME(stime);
        g_free(stime);

    }
    else{
        tv = simTime();
    }

    // update time if this question is a duplicate
    if ((qj = find_job(key)))
    {
        if (tv < qj->delivery)
        {
            qj->delivery = tv;
            timeEventSet->updateTimeEvent(qj->e, tv);
        }
    }
    else{
        // create new job..
        qj = new_job(key);
        qj->delivery = tv;

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(qj);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSQueryScheduler::elapseCallback);

        timeEventSet->addTimeEvent(e);

    }

}

void MDNSQueryScheduler::done(ODnsExtension::MDNSQueryJob* qj){
    qj->done = 1;
    jobs = g_list_remove(jobs, qj);
    history = g_list_append(history, qj);
    simtime_t now = simTime();
    qj->delivery = now;

    // update the time event

    // add random deferral value between 20 and 120
    int defer = intrand(100) + 20;
    // create simtime value from random deferral value
    char* stime = g_strdup_printf("%dms", defer);
    simtime_t tv = STR_SIMTIME(stime);
    g_free(stime);

    timeEventSet->updateTimeEvent(qj->e, now+tv);
}

void MDNSQueryScheduler::check_dup(ODnsExtension::MDNSKey* key)
{
    MDNSQueryJob* qj;

    if((qj = find_job(key))){
        // found a matching upcoming job, we don't need
        // to perform it anymore, since another node
        // queried for it.

        done(qj);
        return;
    }

    // add random deferral value between 20 and 120
    int defer = intrand(100) + 20;
    // create simtime value from random deferral value
    char* stime = g_strdup_printf("%dms", defer);
    simtime_t tv = simTime() + STR_SIMTIME(stime);
    g_free(stime);

    if((qj = find_history(key))){
        // just update the time for the existing job
        qj->delivery = tv;
        timeEventSet->updateTimeEvent(qj->e, tv);
    }
    else{
        qj = new_job(key); // create a new job, since this one is not in the history

        qj->delivery = tv;

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(qj);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSQueryScheduler::elapseCallback);

        timeEventSet->addTimeEvent(e);
    }

}

ODnsExtension::MDNSQueryJob* MDNSQueryScheduler::new_job(ODnsExtension::MDNSKey* key)
{
    MDNSQueryJob *qj = (MDNSQueryJob*) malloc(sizeof(qj));
    qj->id = id_count++;
    qj->key->name = g_strdup(key->name);
    qj->key->type = key->type;
    qj->key->_class = key->_class;

    qj->done = 0;

    jobs = g_list_append(jobs, qj);

    return qj;
}

void MDNSQueryScheduler::remove_job(ODnsExtension::MDNSQueryJob* qj)
{
    timeEventSet->removeTimeEvent(qj->e);

    if(find_job(qj->key)){
        jobs = g_list_remove(jobs, qj);
        g_free(qj->key->name);
        g_free(qj->key);
        g_free(qj);
        return;
    }
    else if(find_history(qj->key)){
        jobs = g_list_remove(jobs, qj);
        g_free(qj->key->name);
        g_free(qj->key);
        g_free(qj);
        return;
    }

    // no ref found? i.e. just delete ...
    g_free(qj->key->name);
    g_free(qj->key);
    g_free(qj);
}

} /* namespace ODnsExtension */
