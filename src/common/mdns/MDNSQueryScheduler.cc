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

MDNSQueryScheduler::MDNSQueryScheduler(ODnsExtension::TimeEventSet* _timeEventSet, UDPSocket* _outSock, void* resolver)
{

    timeEventSet = _timeEventSet;
    outSock = _outSock;
    history = NULL;
    jobs = NULL;

    this->resolver = resolver;

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

    int packetSize = 12; // initial header size

    GList* qlist = NULL;
    GList* anlist = NULL;
    GList* nslist = NULL;
    GList* arlist = NULL;

    int qdcount = 0;
    int ancount = 0;
    int nscount = 0;
    int arcount = 0;

    int success = append_question(qj->key, &qlist, &anlist, &packetSize, &qdcount, &ancount);
    done(qj);

    // now try to append more questions if we didn't already exceed the packet size.
    GList* head = g_list_first(jobs);
    while(success && head){
        // take another query job from the list..
        MDNSQueryJob* job = (MDNSQueryJob*) head->data;
        success = append_question(job->key, &qlist, &anlist, &packetSize, &qdcount, &ancount);
        head = g_list_next(head);
        done(job);
    }

    if(preparePacketAndSend(qlist, anlist, nslist, arlist, qdcount, ancount, nscount, arcount, packetSize, !success)){
        // success, delegate?
    }
    else{
        // some error message?
    }

}

int MDNSQueryScheduler::preparePacketAndSend(GList* qlist, GList* anlist, GList* nslist, GList* arlist, int qdcount, int ancount, int nscount, int arcount, int packetSize, int TC){
    char* msgname = g_strdup_printf("mdns_query#%d", id_count);
    DNSPacket* p = ODnsExtension::createNQuery(msgname, qdcount, ancount, nscount, arcount, id_count++, 0);

    int i = 0;
    // append questions
    GList* next = g_list_first(qlist);
    while(next){
        ODnsExtension::appendQuestion(p, (DNSQuestion*) next->data, i);
        i++;
        next = g_list_next(next);
    }

    // append answers if available
    if(ancount > 0){
        i = 0;
        next = g_list_first(anlist);
        while(next){
            ODnsExtension::appendAnswer(p, (DNSRecord*) next->data, i);
            i++;
            next = g_list_next(next);
        }
    }

    // append auth if available
    if(nscount > 0){
        i = 0;
        next = g_list_first(nslist);
        while(next){
            ODnsExtension::appendAuthority(p, (DNSRecord*) next->data, i);
            i++;
            next = g_list_next(next);
        }
    }

    // append add if available
    if(arcount > 0){
        i = 0;
        next = g_list_first(arlist);
        while(next){
            ODnsExtension::appendAdditional(p, (DNSRecord*) next->data, i);
            i++;
            next = g_list_next(next);
        }
    }

    // packet fully initialized, send it via multicast
    p->setByteLength(packetSize);
    outSock->sendTo(p, multicast_address, MDNS_PORT);

    // packet is out, we're finished
    return 1;
}

int MDNSQueryScheduler::append_question(MDNSKey* key, GList** qlist, GList** anlist, int *packetSize, int* qdcount, int* ancount){
    GList* knownAnswers = NULL; // append known answers from the cache in here

    ODnsExtension::DNSQuestion* q;
    q = createQuestionFromKey(key);

    int qsize = sizeof(key->name) + 4; // name length + 4 bytes for type and class

    if(*packetSize + qsize > MAX_MDNS_PACKET_SIZE){
        return 0;
    }

    *packetSize += qsize;

    (*qdcount)++; // this throws a warning, but we actually want to increase the referenced value ..
    *qlist = g_list_append(*qlist, q);


    // append known answers for this query
    knownAnswers = append_cache_entries(key, knownAnswers);

    // try to append known answers, as long as max size is not exceeded
    GList* next = g_list_first(knownAnswers);
    while(next){
        DNSRecord* record = (DNSRecord*) next->data;

        // calculate size
        int size = 10 + sizeof(record->rname) + record->rdlength;

        if(*packetSize + size > MAX_MDNS_PACKET_SIZE){
            return 0;
        }

        *packetSize += size;

        // append record to answer list
        (*ancount)++;
        *anlist = g_list_append(*anlist, record);

        next = g_list_next(next);
    }
    // all answers were appended, return success
    return 1;
}

GList* MDNSQueryScheduler::append_cache_entries(MDNSKey* key, GList* list){
    char* hash = g_strdup_printf("%s:%s:%s", key->name, getTypeStringForValue(key->type), getClassStringForValue(key->_class));
    GList* from_cache = cache->get_from_cache(hash);
    from_cache = g_list_first(from_cache);
    DNSRecord* record;

    while (from_cache)
    {
        record = (ODnsExtension::DNSRecord*) from_cache->data;

        // try to append known answer if halfTTL not outlived..
        if(cache->halfTTL(record)){
            // everything is fine, we can append the answer..
            // FIXME: create a copy of the record, this way it is
            // too unsafe.
            list = g_list_append(list, record);
        }

        from_cache = g_list_next(from_cache);
    }

    return list;

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

        qj->e = e;
        timeEventSet->addTimeEvent(e);

    }

    callback(&tv, resolver);

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
    /*else{
        qj = new_job(key); // create a new job, since this one is not in the history

        qj->delivery = tv;

        ODnsExtension::TimeEvent* e = new ODnsExtension::TimeEvent(this);
        e->setData(qj);
        e->setExpiry(tv);
        e->setLastRun(0);
        e->setCallback(ODnsExtension::MDNSQueryScheduler::elapseCallback);

        qj->e = e;
        timeEventSet->addTimeEvent(e);
    }*/

}

ODnsExtension::MDNSQueryJob* MDNSQueryScheduler::new_job(ODnsExtension::MDNSKey* key)
{
    MDNSQueryJob *qj = (MDNSQueryJob*) malloc(sizeof(*qj));
    qj->id = id_count++;
    qj->key = (MDNSKey*) malloc(sizeof(MDNSKey*));
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
        history = g_list_remove(history, qj);
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
