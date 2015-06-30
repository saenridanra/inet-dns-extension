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

/**
 * This section defines different omnet++ signals.
 */

simsignal_t MDNSResolver::mdnsQueryRcvd = registerSignal("mdnsQueryRcvd");
simsignal_t MDNSResolver::mdnsQuerySent = registerSignal("mdnsQuerySent");
simsignal_t MDNSResolver::mdnsResponseRcvd = registerSignal("mdnsResponseRcvd");
simsignal_t MDNSResolver::mdnsResponseSent = registerSignal("mdnsResponseSent");
simsignal_t MDNSResolver::mdnsProbeRcvd = registerSignal("mdnsProbeRcvd");
simsignal_t MDNSResolver::mdnsProbeSent = registerSignal("mdnsProbeSent");

simsignal_t MDNSResolver::privateQueryRcvd = registerSignal("privateQueryRcvd");
simsignal_t MDNSResolver::privateQuerySent = registerSignal("privateQuerySent");
simsignal_t MDNSResolver::privateResponseRcvd = registerSignal("privateResponseRcvd");
simsignal_t MDNSResolver::privateResponseSent = registerSignal("privateResponseSent");
simsignal_t MDNSResolver::privateProbeRcvd = registerSignal("privateProbeRcvd");
simsignal_t MDNSResolver::privateProbeSent = registerSignal("privateProbeSent");

MDNSResolver::MDNSResolver()
{
}

MDNSResolver::~MDNSResolver()
{
    // delete objects used in here..
    // print the cache ..
#ifdef DEBUG_ENABLED
    std::unordered_map<std::string, std::list<std::shared_ptr<INETDNS::DNSTimeRecord>>>cache_table =
    cache->get_cache_table();

    std::cout << "*********************** Printing Cache of " << hostname
    << " ***********************\n";
    for (auto kv : cache_table)
    {
        std::cout << "Cache entries exist for for " << kv.first << std::endl;
    }

    std::cout << "--------------- Online Friends of " << hostname
    << " ----------------\n";
    for (auto kv : *friend_data_table)
    {
        if(! kv.second) continue;
        std::shared_ptr<INETDNS::FriendData> fdata = kv.second;
        std::cout << fdata->pdata->friend_id << " online: " << fdata->online
        << std::endl;

    }
#endif

    delete timeEventSet;
    delete probeScheduler;
    delete queryScheduler;
    delete responseScheduler;
}

void MDNSResolver::initialize(int stage)
{
    if (stage == inet::INITSTAGE_LOCAL)
    {
        outSock.setOutputGate(gate("mdnsOut"));
        outSock.bind(MDNS_PORT);
        outSock.setTimeToLive(15);

        privacySock.setOutputGate(gate("privacyOut"));
        privacySock.bind(DEFAULT_PRIVACY_SOCKET_PORT);
        privacySock.setTimeToLive(15);

        // find out whether the module needs to be configured statically
        static_configuration = par("static_configuration").boolValue();

        state = RUNNING;

        private_service_table =
                new std::unordered_map<std::string, std::shared_ptr<INETDNS::PrivateMDNSService>>();
        friend_data_table = new std::unordered_map<std::string, std::shared_ptr<INETDNS::FriendData>>();
        instance_name_table = new std::unordered_map<std::string, std::shared_ptr<INETDNS::FriendData>>();

    }
    else if (stage == inet::INITSTAGE_LAST)
    {
        // join multicast groups
        inet::MulticastGroupList mgl = inet::getModuleFromPar<inet::IInterfaceTable>(par("interfaceTableModule"), this)->collectMulticastGroups();
        outSock.joinLocalMulticastGroups(mgl);

        announcer_state = INETDNS::AnnouncerState::START;
        cDisplayString& dispStr = this->getParentModule()->getDisplayString();
        dispStr.parse("i=device/laptop,#800000");

        timeEventSet = new INETDNS::TimeEventSet();
        selfMessage = new cMessage("timer");
        selfMessage->setKind(MDNS_KIND_TIMER);

        cache = new INETDNS::DNSTTLCache();

        probeScheduler = new INETDNS::MDNSProbeScheduler(timeEventSet, &outSock, this);
        probeScheduler->setCache(cache);
        probeScheduler->setCallback(MDNSResolver::callback);
        queryScheduler = new INETDNS::MDNSQueryScheduler(timeEventSet, &outSock, this);
        queryScheduler->setCache(cache);
        queryScheduler->setCallback(MDNSResolver::callback);
        responseScheduler = new INETDNS::MDNSResponseScheduler(timeEventSet, &outSock, this);
        responseScheduler->setAuthCache(cache);
        responseScheduler->setCallback(MDNSResolver::callback);

        // Set the receivers
        probeScheduler->setSignalReceiver(this);
        queryScheduler->setSignalReceiver(this);
        responseScheduler->setSignalReceiver(this);

        // With static configuration, parameters should have
        // been set in stage 2
        if (static_configuration)
        {
            hostname = par("hostname").stdstringValue();
            hasPrivacy = par("hasPrivacy").boolValue();
            isQuerying = par("isQuerying").boolValue();
            if (hasPrivacy)
                own_instance_name = par("own_instance_name").stdstringValue();

            // in this simple configuration, the resolver goes online
            // after a random amount of time between 0s to 10s
            int rand_delay = intrand(10); // 0 - 10 s random delay
            std::string stime = std::to_string(rand_delay) + std::string("s");
            last_schedule = simTime() + elapseTime + STR_SIMTIME(stime.c_str());
            scheduleAt(last_schedule, selfMessage);

            initializeServices();

            if (hasPrivacy)
            {
                initializePrivateServices();
            }
        }
        else
        {
            // all params have been initialized already
            // by the configurator, we only assign the first schedule based on the uptimes

            probeScheduler->setPrivacyData(private_service_table, friend_data_table, instance_name_table, &privacySock);
            queryScheduler->setPrivacyData(private_service_table, friend_data_table, instance_name_table, &privacySock);
            responseScheduler->setPrivacyData(private_service_table, friend_data_table, instance_name_table,
                    &privacySock);

            scheduleAt(simTime() + uptimes[0]->first, selfMessage);
            current_uptime = 0;
        }

        std::vector<std::string> serviceList;
        for(auto service : services){
            serviceList.push_back(service->name + service->service_type);
        }

        if(isQuerying){
            mdnsTrafficGenerator = new INETDNS::MDNSTrafficGenerator(probeScheduler, queryScheduler, responseScheduler, timeEventSet, &outSock, serviceList);

            if(hasPrivacy){
                mdnsTrafficGenerator->setPrivacyData(private_service_table, friend_data_table, instance_name_table, &privacySock);
            }
        }

        try{
            hostaddress4 = inet::L3AddressResolver().addressOf(this->getParentModule(), inet::L3AddressResolver::ADDR_IPv4);
        }
        catch(int e){

        }

//        FIXME: Can't set IPv6 since update to INET 3.0
//        try{
//            hostaddress6 = inet::L3Address(hostaddress4.toIPv6());
//        }
//        catch(int e){
//
//        }

        announcer = new INETDNS::MDNSAnnouncer(probeScheduler, responseScheduler, timeEventSet, services,
                hostname, &hostaddress4, 0);

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
        else if (msg->getKind() == inet::UDP_I_DATA)
        {
            DNSPacket* p = check_and_cast<DNSPacket*>(msg);
            inet::UDPDataIndication *ctrl = check_and_cast<inet::UDPDataIndication *>(p->getControlInfo());
            inet::L3Address srcAddress = ctrl->getSrcAddr();

            if (srcAddress != inet::IPv4Address().LOOPBACK_ADDRESS)
            {
                if (INETDNS::isQuery(p))
                {
                    if(INETDNS::isProbe(p)){
                        if(p->par("private"))
                            emit(MDNSResolver::privateProbeRcvd, p);
                        else
                            emit(MDNSResolver::mdnsProbeRcvd, p);
                    }
                    else{
                        if(p->par("private"))
                            emit(MDNSResolver::privateQueryRcvd, p);
                        else
                            emit(MDNSResolver::mdnsQueryRcvd, p);
                    }

                    handleQuery(p);
                }
                else if (INETDNS::isResponse(p))
                {
                    if(p->par("private"))
                        emit(MDNSResolver::privateResponseRcvd, p);
                    else
                        emit(MDNSResolver::mdnsResponseRcvd, p);

                    handleResponse(p);
                }
            }

            delete msg;
            return;
        }
        else
        {
            delete msg;
            return;
        }

    }
}

void MDNSResolver::elapsedTimeCheck()
{

    // check if we have an event coming up now, i.e. check if we can get
    // an event from the timeEventSet
    if (state == RUNNING)
    {
        if (!static_configuration && uptimes[current_uptime]->second <= simTime())
        {
            state = SHUTDOWN;
            // initiate shudown
            // flush existing schedule
            // goodbye all announced services
            announcer->shutdown();
            if(isQuerying)
                mdnsTrafficGenerator->stopQuerying();
        }

        INETDNS::TimeEvent* event;
        while ((event = timeEventSet->getTimeEventIfDue()))
        {
            // perform the timeEvent..
            event->performCallback(); // the rest is handled in the callback
        }

        if (announcer_state != announcer->getState())
        {
            announcer_state = announcer->getState();

            if (INETDNS::AnnouncerState::PROBE == announcer_state)
            { // Setting a module's position, icon and status icon:
#ifdef DEBUG_ENABLED
                const char* hostname_announced = "HOSTNAME ANNOUNCED, START PROBING";
                this->getParentModule()->bubble(hostname_announced);
                cDisplayString& dispStr = this->getParentModule()->getDisplayString();
                dispStr.parse("i=device/laptop,orange");
#endif
            }
            else if (INETDNS::AnnouncerState::FINISHED == announcer_state)
            { // Setting a module's position, icon and status icon:
#ifdef DEBUG_ENABLED
                const char* finished_probing = "FINISHED PROBING";
                this->getParentModule()->bubble(finished_probing);
                cDisplayString& dispStr = this->getParentModule()->getDisplayString();
                dispStr.parse("i=device/laptop,#449544,100");
#endif
                if(isQuerying)
                    mdnsTrafficGenerator->startQuerying();
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
    else if (state == SHUTDOWN)
    {
        if (current_uptime == uptimes.size() - 1)
            return;
        if (uptimes[current_uptime + 1]->first <= simTime())
        {
            // start announcing again
            announcer->initialize();
            state = RUNNING;
        }
    }

}

void MDNSResolver::callback(std::shared_ptr<void> data, void* thispointer)
{
    MDNSResolver * self = static_cast<MDNSResolver*>(thispointer);
    std::shared_ptr<simtime_t> tv = std::static_pointer_cast < simtime_t > (data);
    self->scheduleSelfMessage(*tv);
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
    std::list<std::shared_ptr<DNSRecord>> record_list;

    // perform a cache cleanup, every entry that has passed
    // it's TTL was not successfully updated
    cache->cleanup();

    // go through the question section, find out which answers to respond with
    for (int i = 0; i < p->getQdcount(); i++)
    {
        INETDNS::DNSQuestion question = p->getQuestions(i);
        std::shared_ptr<INETDNS::MDNSKey> key = INETDNS::mdns_key_new(question.qname, question.qtype,
                question.qclass);
        // allow suppression if there are no answers for this query
        // and the tc flag is not set
        if (p->getAncount() == 0 && !DNS_HEADER_TC(p->getOptions()))
            queryScheduler->check_dup(key);

        // prepare matching responses
        std::list<std::shared_ptr<DNSRecord>> announced_records = announcer->get_announced_services();

        for (auto it = announced_records.begin(); it != announced_records.end(); ++it)
        {
            // check if the record matches the key, if so append it to the answer list
            std::shared_ptr<DNSRecord> r = *it;
            std::shared_ptr<INETDNS::MDNSKey> record_key = INETDNS::mdns_key_new(r->rname, r->rtype,
                    r->rclass);

            // ANY Question
            if (key->type == DNS_TYPE_VALUE_ANY)
            {
                // only compare name and class
                if (INETDNS::compareMDNSKeyANY(key, record_key))
                {
                    record_list.push_back(r);
                }
            } // Normal Question
            else
            {
                if (INETDNS::compareMDNSKey(key, record_key))
                {
                    record_list.push_back(r);
                }
            }

            // If the question did non include ANY or CNAME, we did not check for CNAMEs just yet
            if (key->type != DNS_TYPE_VALUE_CNAME && key->type != DNS_TYPE_VALUE_ANY)
            {
                std::shared_ptr<INETDNS::MDNSKey> cname_key = INETDNS::mdns_key_new(question.qname,
                DNS_TYPE_VALUE_CNAME, question.qclass);
                if (INETDNS::compareMDNSKey(cname_key, record_key))
                {
                    record_list.push_back(r);
                }

                // free the cname key
                INETDNS::mdns_key_free(cname_key);
            }

            INETDNS::mdns_key_free(record_key);
        }

        // free the question key
        INETDNS::mdns_key_free(key);
    }

    // go through the answer section and perform KAS
    inet::L3Address* querier = &(check_and_cast<inet::UDPDataIndication *>(p->getControlInfo()))->getSrcAddr();
    for (int i = 0; i < p->getAncount(); i++)
    {
        std::shared_ptr<DNSRecord> answer = INETDNS::copyDnsRecord(&p->getAnswers(i));
        responseScheduler->suppress(answer, 0, querier, 0);
        // remove records that we may have appended to the list
        // since the records pointers are different we have to go through the list ..
        for (auto it = record_list.begin(); it != record_list.end(); ++it)
        {
            std::shared_ptr<DNSRecord> in_record = *it;
            if (INETDNS::recordDataEqual(in_record, answer))
            {
                // remove the record from the list ..
                record_list.erase(it++);
            }
        }
    }

    // now check probes and check whether they collide
    for (int i = 0; i < p->getNscount(); i++)
    {
        std::shared_ptr<DNSRecord> ns_record = INETDNS::copyDnsRecord(&p->getAuthorities(i));
        announcer->check_conflict(ns_record); // check whether we have a problem
    }

    // we're finished, now let's post the responses
    for (auto it = record_list.begin(); it != record_list.end(); ++it)
    {
        responseScheduler->post(*it, 0, querier, p->getNscount() > 0);
    }
}

void MDNSResolver::handleResponse(DNSPacket* p)
{
    // go through the answer list of the packet
#ifdef DEBUG_ENABLED
    std::string bubble_popup = "";
#endif
    for (int i = 0; i < p->getAncount(); i++)
    {
        // check if the record conflicts, if not put it into the cache
        std::shared_ptr<DNSRecord> r = INETDNS::copyDnsRecord(&p->getAnswers(i));
        std::string type = std::string(INETDNS::getTypeStringForValue(r->rtype));
        std::string _class = std::string(INETDNS::getClassStringForValue(r->rclass));
        // create hash:
        std::string hash = r->rname + std::string(":") + type + std::string(":") + _class;
        if (r->rtype != DNS_TYPE_VALUE_ANY)
        {
            if (!announcer->check_conflict(r) && !cache->is_in_cache(hash))
            {
                // put the record into the cache
#ifdef DEBUG_ENABLED
                bubble_popup.append("New cache entry:\n");
                bubble_popup.append(r->rname);
                bubble_popup.append(":");
                bubble_popup.append(INETDNS::getTypeStringForValue(r->rtype));
                bubble_popup.append(":");
                bubble_popup.append(INETDNS::getClassStringForValue(r->rclass));
                bubble_popup.append("\nData: ");
                bubble_popup.append(r->strdata.c_str());
                bubble_popup.append("\n---------\n");
#endif

                cache->put_into_cache(INETDNS::copyDnsRecord(r));

                // look if this record belongs to a friend announcing a privacy service
                if (hasPrivacy && r->rtype == DNS_TYPE_VALUE_SRV)
                {
                    // check probe whether it is a friend, then we can set the status to online
                    if (instance_name_table->find(r->rname) != instance_name_table->end())
                    {
                        // the hash table contains the user in question
                        std::shared_ptr<INETDNS::FriendData> fdata = (*instance_name_table)[r->rname];
                        // set to online and last_informed
                        if ((fdata->last_informed < simTime() - STR_SIMTIME("30s")
                                || fdata->last_informed <= STR_SIMTIME("0s")) && !INETDNS::isGoodbye(r))
                        {
                            inet::L3Address querier =
                                    check_and_cast<inet::UDPDataIndication *>(p->getControlInfo())->getSrcAddr();

                            fdata->address = inet::L3Address(querier);

                            // copy address, set it in fdata
                            fdata->address = querier;
                            fdata->last_informed = simTime();
                            fdata->online = 1;

                            std::shared_ptr<DNSRecord> record(new DNSRecord());
                            record->rname = own_instance_name + std::string("._privacy._tcp.local");
                            record->rtype = DNS_TYPE_VALUE_SRV;
                            record->rclass = DNS_CLASS_IN;
                            record->ttl = 60 * 75;

                            std::shared_ptr<INETDNS::SRVData> srv(new INETDNS::SRVData());
                            srv->name = record->rname;
                            srv->service = std::string("._privacy._tcp.local");
                            srv->target = hostname + std::string(".local");
                            srv->port = 9977; // TODO: remove hard coded port ..
                            srv->priority = 0;
                            srv->weight = 0;
                            srv->proto = "_tcp";
                            srv->ttl = 60 * 75;

                            record->rdata = srv;
                            record->rdlength = 6 + srv->name.length() + srv->service.length() + srv->target.length();

#ifdef DEBUG_ENABLED
                            std::cout << "[" << hostname << "]: Friend " << fdata->pdata->friend_id << " came online\n";
#endif
                            //responseScheduler->post(record, 0, NULL, 0); // post our own response into the scheduler
                            // it will be checked and sent via the privacy socket
                        }
                        else if (INETDNS::isGoodbye(r))
                        {
                            // user went offline
#ifdef DEBUG_ENABLED
                            std::cout << "[" << fdata->pdata->friend_id << "] went offline" << std::endl;
#endif
                            fdata->online = 0;
                        }
                    }
                }

                responseScheduler->check_dup(r, 0);
            }
        }
    }

#ifdef DEBUG_ENABLED
    if (bubble_popup != "")
    {
        EV << bubble_popup.c_str();
        this->getParentModule()->bubble(bubble_popup.c_str());
    }
#endif
}

void MDNSResolver::initializeServices()
{
    std::string service_files = par("service_files").stdstringValue();
    // go through all files and initialize them as MDNS services
    cStringTokenizer tokenizer(service_files.c_str());
    std::string token;

    while (tokenizer.hasMoreTokens())
    {
        // initialize service file
        token = std::string(tokenizer.nextToken());
        initializeServiceFile(token);
    }
}

void MDNSResolver::initializeServiceFile(std::string file)
{
    std::string line;
    std::fstream service_file(file, std::ios::in);
    int error = 0;

    std::shared_ptr<INETDNS::MDNSService> service(new INETDNS::MDNSService);

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
            service->service_type = tokens[1];
        }
        else if (tokens[0] == "instance_name")
        {
            service->name = tokens[1];
        }
        else if (tokens[0] == "txt_record")
        {
            service->txtrecords.push_back(tokens[1].c_str());
        }
        else if (tokens[0] == "port")
        {
            char* tail;
            service->port = strtol(tokens[1].c_str(), &tail, 10);
        }
        else
        {
            error = 1;
            cRuntimeError("Malformed service file %s", file.c_str());
        }

    }

    if (!error)
    {
        services.push_back(service);
    }

}

void MDNSResolver::initializePrivateServices()
{

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
        std::string crypto_key;
        std::string friend_id;
        std::string privacy_service_instance_name;

        while (inner_tokenizer.hasMoreTokens())
        {
            inner_token = inner_tokenizer.nextToken();
            // the format of pairing data is fixed, first the friend id
            // then the privacy_instance_name and then the crypto key
            switch (pos)
            {
                case 0:
                    friend_id = std::string(inner_token);
                    break;
                case 1:
                    privacy_service_instance_name = std::string(inner_token);
                    break;
                case 2:
                    crypto_key = std::string(inner_token);
                    break;
                default:
                    break;
            }

            pos++;
        }

        // create a pairing data and friend data object, insert it into the hash table
        std::shared_ptr<INETDNS::PairingData> pdata = INETDNS::pairing_data_new(crypto_key, friend_id,
                privacy_service_instance_name);
        std::shared_ptr<INETDNS::FriendData> fdata = INETDNS::friend_data_new(pdata,
        DEFAULT_PRIVACY_SOCKET_PORT);

#ifdef DEBUG_ENABLED
        std::cout << "[" << hostname << "]: Adding friend " << friend_id << " with instance name "
                << privacy_service_instance_name << "\n";
#endif
        (*friend_data_table)[friend_id] = fdata;
        (*instance_name_table)[privacy_service_instance_name] = fdata;
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

        std::list<std::string> offered_to;
        std::list<std::string> offered_by;
        std::string stype;
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
                stype = tokens[1];
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
                    offered_to.push_back(offers[i]);
            }
            else if (tokens[0] == "offered_by")
            {
                // parse list, comma separated
                std::vector<std::string> offers = cStringTokenizer(tokens[1].c_str(), ",").asVector();
                // put the offers into the list
                for (unsigned int i = 0; i < offers.size(); i++)
                    offered_by.push_back(offers[i]);
            }
            else
            {
                cRuntimeError("Unrecognized line parsing private service file %s.", file);
            }

        }

        // now populate the private service object, store it in the hash table
        std::shared_ptr<INETDNS::PrivateMDNSService> psrv = INETDNS::private_service_new(stype, is_private);
        psrv->offered_to = offered_to;
        psrv->offered_by = offered_by;
        (*private_service_table)[stype] = psrv;

    }

}

void MDNSResolver::receiveSignal(std::unordered_map<std::string, int> parMap, void* additionalPayload){
    if(parMap.find("signal_type") == parMap.end() || parMap.find("privacy") == parMap.end())
        throw cRuntimeError("One or more arguments are missing.");

    int type = parMap["signal_type"];
    int privacy = parMap["privacy"];
    cPacket* payload = (cPacket*) additionalPayload;

    switch(type){
        case 0:
            if(privacy)
                emit(MDNSResolver::privateProbeSent, payload);
            else
                emit(MDNSResolver::mdnsProbeSent, payload);
            break;
        case 1:
            if(privacy)
                emit(MDNSResolver::privateQuerySent, payload);
            else
                emit(MDNSResolver::mdnsQuerySent, payload);
            break;
        case 2:
            if(privacy)
                emit(MDNSResolver::privateResponseSent, payload);
            else
                emit(MDNSResolver::mdnsResponseSent, payload);
            break;
        default: throw cRuntimeError("Signal Type unkown.");
    }
}

void MDNSResolver::notify(){
    // Reschedule event based on latest event due
    INETDNS::TimeEvent* event = timeEventSet->getTopElement();

    if(event->getExpiry() < last_schedule){
        cancelAndDelete(selfMessage);
        scheduleAt(event->getExpiry(), selfMessage);
        last_schedule = event->getExpiry();
    }
}
