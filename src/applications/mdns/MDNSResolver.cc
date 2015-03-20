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

MDNSResolver::MDNSResolver()
{
}

MDNSResolver::~MDNSResolver()
{
    // delete objects used in here..
    // print the cache ..
    GHashTable* cache_table = cache->get_cache_table();
    GHashTableIter iterator;
    gpointer key, value;
    g_printf("*********************** Printing Cache of %s ***********************\n", hostname);
    g_hash_table_iter_init(&iterator, cache_table);
    while (g_hash_table_iter_next(&iterator, &key, &value))
    {
        char* hash = (char*) key;
        g_printf("Cache entries exist for for %s: \n", hash);

    }

    g_printf("--------------- Online Friends of %s ----------------\n", hostname);
    g_hash_table_iter_init(&iterator, friend_data_table);
    while (g_hash_table_iter_next(&iterator, &key, &value))
    {
        ODnsExtension::FriendData* fdata = (ODnsExtension::FriendData*) value;
        g_printf("%s online: %d \n", fdata->pdata->friend_id, fdata->online);

    }

    g_free(hostname);
    delete timeEventSet;
    delete probeScheduler;
    delete queryScheduler;
    delete responseScheduler;
}

void MDNSResolver::initialize(int stage)
{
    if (stage == 0)
    {
        outSock.setOutputGate(gate("mdnsOut"));
        outSock.bind(MDNS_PORT);
        outSock.setTimeToLive(15);

        privacySock.setOutputGate(gate("privacyOut"));
        privacySock.bind(DEFAULT_PRIVACY_SOCKET_PORT);
        privacySock.setTimeToLive(15);

    }
    else if (stage == 3)
    {

        announcer_state = ODnsExtension::AnnouncerState::START;
        cDisplayString& dispStr = this->getParentModule()->getDisplayString();
        dispStr.parse("i=device/laptop,#800000");

        timeEventSet = new ODnsExtension::TimeEventSet();
        selfMessage = new cMessage("timer");
        selfMessage->setKind(MDNS_KIND_TIMER);

        outSock.joinLocalMulticastGroups();

        int rand_delay = intrand(10); // 0 - 10 s random delay
        char* stime = g_strdup_printf("%ds", rand_delay);
        last_schedule = simTime() + elapseTime + STR_SIMTIME(stime);
        g_free(stime);
        scheduleAt(last_schedule, selfMessage);

        cache = new ODnsExtension::DNSTTLCache();

        probeScheduler = new ODnsExtension::MDNSProbeScheduler(timeEventSet, &outSock, this);
        probeScheduler->setCache(cache);
        probeScheduler->setCallback(MDNSResolver::callback);
        queryScheduler = new ODnsExtension::MDNSQueryScheduler(timeEventSet, &outSock, this);
        queryScheduler->setCache(cache);
        queryScheduler->setCallback(MDNSResolver::callback);
        responseScheduler = new ODnsExtension::MDNSResponseScheduler(timeEventSet, &outSock, this);
        responseScheduler->setCache(cache);
        responseScheduler->setCallback(MDNSResolver::callback);

        hostname = g_strdup(par("hostname").stringValue());
        hostaddress = IPvXAddressResolver().addressOf(this->getParentModule());
        hasPrivacy = par("hasPrivacy").boolValue();

        services = NULL;
        initializeServices();

        if (hasPrivacy)
        {
            own_instance_name = par("own_instance_name").stringValue();
            initializePrivateServices();
        }

        announcer = new ODnsExtension::MDNSAnnouncer(probeScheduler, responseScheduler, timeEventSet, services,
                hostname, &hostaddress);

        announcer->initialize();
    }
}

void MDNSResolver::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage())
    {
        if (msg->getKind() == MDNS_KIND_TIMER)
        {
            elapsedTimeCheck();
            return;
        }
    }
    else
    {
        // check which kind it is
        if (msg->getKind() == MDNS_KIND_INTERNAL_QUERY)
        {
            // this is a message from a module utilizing the mdns resolver
            // and wanting to perform a query..
            delete msg;
            return;
        }
        else if (msg->getKind() == MDNS_KIND_INTERNAL_PUBLISH)
        {
            // a higher layer application wants to publish a service
            delete msg;
            return;
        }
        else if (msg->getKind() == MDNS_KIND_INTERNAL_REVOKE)
        {
            // a higher layer application wants to revoke a service offered
            delete msg;
            return;
        }
        else if (msg->getKind() == UDP_I_DATA)
        {
            DNSPacket* p = check_and_cast<DNSPacket*>(msg);
            UDPDataIndication *ctrl = check_and_cast<UDPDataIndication *>(p->getControlInfo());
            IPvXAddress srcAddress = ctrl->getSrcAddr();

            if (srcAddress.get4() != hostaddress.get4())
            {
                if (ODnsExtension::isQuery(p))
                {
                    handleQuery(p);
                }
                else if (ODnsExtension::isResponse(p))
                {
                    handleResponse(p);
                }
            }

            delete msg;
            return;
        }

    }
}

void MDNSResolver::elapsedTimeCheck()
{

    // check if we have an event coming up now, i.e. check if we can get
    // an event from the timeEventSet
    ODnsExtension::TimeEvent* event;
    while ((event = timeEventSet->getTimeEventIfDue()))
    {
        // perform the timeEvent..
        event->performCallback(); // the rest is handled in the callback
    }

    if (announcer_state != announcer->getState())
    {
        announcer_state = announcer->getState();

        if(ODnsExtension::AnnouncerState::PROBE == announcer_state){// Setting a module's position, icon and status icon:
                const char* hostname_announced = "HOSTNAME ANNOUNCED, START PROBING";
                this->getParentModule()->bubble(hostname_announced);
                cDisplayString& dispStr = this->getParentModule()->getDisplayString();
                dispStr.parse("i=device/laptop,orange");
        }
        else if(ODnsExtension::AnnouncerState::FINISHED == announcer_state){// Setting a module's position, icon and status icon:
                const char* finished_probing = "FINISHED PROBING";
                this->getParentModule()->bubble(finished_probing);
                cDisplayString& dispStr = this->getParentModule()->getDisplayString();
                dispStr.parse("i=device/laptop,#449544,100");
        }
    }

    event = timeEventSet->getTopElement();

    // first, schedule new elapseTimeCheck

    if (event)
    {
        scheduleAt(event->getExpiry(), selfMessage);
        last_schedule = event->getExpiry();
    }

}

void MDNSResolver::callback(void* data, void* thispointer)
{
    MDNSResolver * self = static_cast<MDNSResolver*>(thispointer);
    self->scheduleSelfMessage(*(simtime_t*) data);
}

void MDNSResolver::scheduleSelfMessage(simtime_t tv)
{
    if (tv < last_schedule)
    {
        cancelEvent(selfMessage);
        scheduleAt(tv, selfMessage);
    }
}

void MDNSResolver::handleQuery(DNSPacket* p)
{
    // go through the ns section of the query
    GList* record_list = NULL;

    // perform a cache cleanup, every entry that has passed
    // it's TTL was not successfully updated
    cache->cleanup();

    // go through the question section, find out which answers to respond with
    for (int i = 0; i < p->getQdcount(); i++)
    {
        ODnsExtension::DNSQuestion question = p->getQuestions(i);
        ODnsExtension::MDNSKey* key = ODnsExtension::mdns_key_new(question.qname, question.qtype, question.qclass);
        // allow suppression if there are no answers for this query
        // and the tc flag is not set
        if (p->getAncount() == 0 && !DNS_HEADER_TC(p->getOptions()))
            queryScheduler->check_dup(key);

        // prepare matching responses
        GList* announced_records = announcer->get_announced_services();

        while (announced_records)
        {
            // check if the record matches the key, if so append it to the answer list
            DNSRecord* r = (DNSRecord*) announced_records->data;
            ODnsExtension::MDNSKey* record_key = ODnsExtension::mdns_key_new(r->rname, r->rtype, r->rclass);

            // ANY Question
            if (key->type == DNS_TYPE_VALUE_ANY)
            {
                // only compare name and class
                if (ODnsExtension::compareMDNSKeyANY(key, record_key))
                {
                    record_list = g_list_append(record_list, r);
                }
            } // Normal Question
            else
            {
                if (ODnsExtension::compareMDNSKey(key, record_key))
                {
                    record_list = g_list_append(record_list, r);
                }
            }

            // If the question did non include ANY or CNAME, we did not check for CNAMEs just yet
            if (key->type != DNS_TYPE_VALUE_CNAME && key->type != DNS_TYPE_VALUE_ANY)
            {
                ODnsExtension::MDNSKey* cname_key = ODnsExtension::mdns_key_new(question.qname, DNS_TYPE_VALUE_CNAME,
                        question.qclass);
                if (ODnsExtension::compareMDNSKey(cname_key, record_key))
                {
                    record_list = g_list_append(record_list, r);
                }

                // free the cname key
                ODnsExtension::mdns_key_free(cname_key);
            }

            ODnsExtension::mdns_key_free(record_key);
            announced_records = g_list_next(announced_records);
        }

        // free the question key
        ODnsExtension::mdns_key_free(key);
    }

    // go through the answer section and perform KAS
    IPvXAddress* querier = &(check_and_cast<UDPDataIndication *>(p->getControlInfo()))->getSrcAddr();
    for (int i = 0; i < p->getAncount(); i++)
    {
        DNSRecord* answer = &p->getAnswers(i);
        responseScheduler->suppress(answer, 0, querier, 0);
        // remove records that we may have appended to the list
        // since the records pointers are different we have to go through the list ..
        GList* next = g_list_first(record_list);
        while (next)
        {
            DNSRecord* in_record = (DNSRecord*) next->data;
            next = g_list_next(next);
            if (!g_strcmp0(answer->rname, in_record->rname) && !g_strcmp0(answer->rdata, in_record->rdata)
                    && answer->rtype == in_record->rtype && answer->rclass == in_record->rclass)
            {
                // remove the record from the list ..
                record_list = g_list_remove(record_list, in_record);
            }
        }
    }

    // now check probes and check whether they collide
    for (int i = 0; i < p->getNscount(); i++)
    {
        DNSRecord* ns_record = (DNSRecord*) &p->getAuthorities(i);
        announcer->check_conflict(ns_record); // check whether we have a problem
    }

    // we're finished, now let's post the responses
    GList* next = g_list_first(record_list);
    while (next)
    {
        responseScheduler->post((DNSRecord*) next->data, 0, querier, p->getNscount() > 0);
        next = g_list_next(next);
    }
}

void MDNSResolver::handleResponse(DNSPacket* p)
{
    // go through the answer list of the packet
    std::string bubble_popup = "";
    for (int i = 0; i < p->getAncount(); i++)
    {
        // check if the record conflicts, if not put it into the cache
        DNSRecord* r = &p->getAnswers(i);
        const char* type = ODnsExtension::getTypeStringForValue(r->rtype);
        const char* _class = ODnsExtension::getClassStringForValue(r->rclass);
        // create hash:
        char* hash = g_strdup_printf("%s:%s:%s", r->rname, type, _class);
        if (r->rtype != DNS_TYPE_VALUE_ANY)
        {
            if (!announcer->check_conflict(r) && !cache->is_in_cache(hash))
            {
                // put the record into the cache
                bubble_popup.append("New cache entry:\n");
                bubble_popup.append(r->rname);
                bubble_popup.append(":");
                bubble_popup.append(ODnsExtension::getTypeStringForValue(r->rtype));
                bubble_popup.append(":");
                bubble_popup.append(ODnsExtension::getClassStringForValue(r->rclass));
                bubble_popup.append("\nData: ");
                bubble_popup.append(r->rdata);
                bubble_popup.append("\n---------\n");

                cache->put_into_cache(ODnsExtension::copyDnsRecord(r));

                // look if this record belongs to a friend announcing a privacy service
                if (hasPrivacy && r->rtype == DNS_TYPE_VALUE_SRV)
                {
                    // check probe whether it is a friend, then we can set the status to online
                    if (g_hash_table_contains(instance_name_table, r->rname))
                    {
                        // the hash table contains the user in question
                        ODnsExtension::FriendData* fdata = (ODnsExtension::FriendData*) g_hash_table_lookup(
                                instance_name_table, r->rname);
                        // set to online and last_informed
                        if ((fdata->last_informed < simTime() - STR_SIMTIME("30s")
                                || fdata->last_informed <= STR_SIMTIME("0s")) && !ODnsExtension::isGoodbye(r))
                        {
                            IPvXAddress querier =
                                    check_and_cast<UDPDataIndication *>(p->getControlInfo())->getSrcAddr();

                            fdata->address = IPvXAddress(querier.get4());

                            // copy address, set it in fdata
                            fdata->address = querier;
                            fdata->last_informed = simTime();
                            fdata->online = 1;

                            DNSRecord* record = (DNSRecord*) malloc(sizeof(*record));
                            record->rname = g_strdup_printf("%s._privacy._tcp.local", own_instance_name);
                            record->rtype = DNS_TYPE_VALUE_SRV;
                            record->rclass = DNS_CLASS_IN;
                            record->rdata = g_strdup_printf("%s.local", hostname);
                            g_printf("[%s]: Friend %s came online\n", hostname, fdata->pdata->friend_id);
                            responseScheduler->post(record, 0, NULL, 0); // post our own response into the scheduler
                            // it will be checked and sent via the privacy socket
                        }
                        else if (ODnsExtension::isGoodbye(r))
                        {
                            // user went offline
                            fdata->online = 0;
                        }
                    }
                }

                responseScheduler->check_dup(r, 0);
            }
        }
    }

    if (bubble_popup != "")
    {
        EV << bubble_popup.c_str();
        this->getParentModule()->bubble(bubble_popup.c_str());
    }
}

void MDNSResolver::initializeServices()
{
    const char* service_files = par("service_files").stringValue();
    // go through all files and initialize them as MDNS services
    cStringTokenizer tokenizer(service_files);
    const char *token;

    while (tokenizer.hasMoreTokens())
    {
        // initialize service file
        token = tokenizer.nextToken();
        initializeServiceFile(token);
    }
}

void MDNSResolver::initializeServiceFile(const char* file)
{
    std::string line;
    std::fstream service_file(file, std::ios::in);
    int error = 0;

    ODnsExtension::MDNSService* service = (ODnsExtension::MDNSService*) malloc(sizeof(*service));
    service->txtrecords = NULL;

    while (getline(service_file, line, '\n'))
    {

        if (line.empty() || line[0] == ';')
        {

            continue;
        }

        // use a tokenizer to interpret the line
        std::vector<std::string> tokens = cStringTokenizer(line.c_str(), "=").asVector();

        if (tokens.size() != 2)
        {
            continue; // we have exactly two tokens vor our key value pairs
        }

        if (tokens[0] == "service_type")
        {
            service->service_type = g_strdup(tokens[1].c_str());
        }
        else if (tokens[0] == "instance_name")
        {
            service->name = g_strdup(tokens[1].c_str());
        }
        else if (tokens[0] == "txt_record")
        {
            service->txtrecords = g_list_append(service->txtrecords, g_strdup(tokens[1].c_str()));
        }
        else if (tokens[0] == "port")
        {
            char* tail;
            service->port = strtol(tokens[1].c_str(), &tail, 10);
        }
        else
        {
            error = 1;
            cRuntimeError("Malformed service file %s", file);
        }

    }

    if (!error)
    {
        services = g_list_append(services, service);
    }

}

void MDNSResolver::initializePrivateServices()
{
    private_service_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
    NULL);
    friend_data_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
    NULL);
    instance_name_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
    NULL);

    probeScheduler->setPrivacyData(private_service_table, friend_data_table, instance_name_table, &privacySock);
    queryScheduler->setPrivacyData(private_service_table, friend_data_table, instance_name_table, &privacySock);
    responseScheduler->setPrivacyData(private_service_table, friend_data_table, instance_name_table, &privacySock);

    // first read pairing data param and initialize
    const char* pairing_data = par("pairing_data").stringValue();
    // use tokenizer to separate by ; , which separates entries
    cStringTokenizer tokenizer(pairing_data, ";");
    const char *token;
    const char *inner_token;

    while (tokenizer.hasMoreTokens())
    {
        // initialize service file
        token = tokenizer.nextToken();
        // separate by , with new tokenizer
        cStringTokenizer inner_tokenizer(token, ",");
        int pos = 0;
        char* crypto_key;
        char* friend_id;
        char* privacy_service_instance_name;

        while (inner_tokenizer.hasMoreTokens())
        {
            inner_token = inner_tokenizer.nextToken();
            // the format of pairing data is fixed, first the friend id
            // then the privacy_instance_name and then the crypto key
            switch (pos)
            {
                case 0:
                    friend_id = g_strdup(inner_token);
                    break;
                case 1:
                    privacy_service_instance_name = g_strdup(inner_token);
                    break;
                case 2:
                    crypto_key = g_strdup(inner_token);
                    break;
                default:
                    break;
            }

            pos++;
        }

        // create a pairing data and friend data object, insert it into the hash table
        ODnsExtension::PairingData* pdata = ODnsExtension::pairing_data_new(crypto_key, friend_id,
                privacy_service_instance_name);
        ODnsExtension::FriendData* fdata = ODnsExtension::friend_data_new(pdata, DEFAULT_PRIVACY_SOCKET_PORT);

        g_printf("[%s]: Adding friend %s with instance name %s\n", hostname, friend_id, privacy_service_instance_name);
        g_hash_table_insert(friend_data_table, friend_id, fdata);
        g_hash_table_insert(instance_name_table, privacy_service_instance_name, fdata);
    }

    // now initialize private service files

    const char* private_service_files = par("privacy_service_files").stringValue();
    const char* file;
    cStringTokenizer tokenizer2(private_service_files);
    while (tokenizer2.hasMoreTokens())
    {
        // init file by file:
        file = tokenizer2.nextToken();
        std::string line;
        std::fstream private_service_file(file, std::ios::in);

        GList* offered_to = NULL;
        GList* offered_by = NULL;
        char* stype;
        int is_private;

        // go through the lines of the file
        while (getline(private_service_file, line, '\n'))
        {
            // parse line by '=' delimiter
            cStringTokenizer inner_tokenizer(line.c_str(), "=");
            // two tokens, label and value
            std::vector<std::string> tokens = inner_tokenizer.asVector();

            if (tokens.size() != 2)
                cRuntimeError("Error initializing private service file %s", file);

            if (tokens[0] == "type")
            {
                stype = g_strdup(tokens[1].c_str());
            }
            else if (tokens[0] == "is_private")
            {
                if (tokens[1] == "0")
                    is_private = 0;
                else if (tokens[1] == "1")
                    is_private = 1;
                else
                    cRuntimeError("Error initializing private service file %s. Wrong value for is_private", file);
            }
            else if (tokens[0] == "offered_to")
            {
                // parse list, comma separated
                std::vector<std::string> offers = cStringTokenizer(tokens[1].c_str(), ",").asVector();
                // put the offers into the list
                for (unsigned int i = 0; i < offers.size(); i++)
                    offered_to = g_list_append(offered_to, g_strdup(offers[i].c_str()));
            }
            else if (tokens[0] == "offered_by")
            {
                // parse list, comma separated
                std::vector<std::string> offers = cStringTokenizer(tokens[1].c_str(), ",").asVector();
                // put the offers into the list
                for (unsigned int i = 0; i < offers.size(); i++)
                    offered_by = g_list_append(offered_by, g_strdup(offers[i].c_str()));
            }
            else
            {
                cRuntimeError("Unrecognized line parsing private service file %s.", file);
            }

        }

        // now populate the private service object, store it in the hash table
        ODnsExtension::PrivateMDNSService* psrv = ODnsExtension::private_service_new(stype, is_private);
        psrv->offered_to = g_list_first(offered_to);
        psrv->offered_by = g_list_first(offered_by);
        g_hash_table_insert(private_service_table, g_strdup(stype), psrv);

    }

}
