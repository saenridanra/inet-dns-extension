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

#include "DNSServerBase.h"

Define_Module(DNSServerBase);

void DNSServerBase::initialize(int stage)
{
    if (stage == 0)
    {
        cSimpleModule::initialize(stage);
        // Initialize gates
        out.setOutputGate(gate("udpOut"));
        out.bind(DNS_PORT);

        receivedQueries = 0;
    }
    else if (stage == 3)
    {
        rootServers = IPvXAddressResolver().resolve(cStringTokenizer(par("root_servers")).asVector());
    }
}

void DNSServerBase::handleMessage(cMessage *msg)
{
    int isDNS = 0;
    int isQR = 0;
    ODnsExtension::Query* query;
    DNSPacket* response;

    // Check if we received a query
    if (msg->arrivedOn("udpIn"))
    {
        if ((isDNS = ODnsExtension::isDNSpacket((cPacket*) msg)))
        {
            if ((isQR = ODnsExtension::isQueryOrResponse((cPacket*) msg)) == 0)
            {

                query = ODnsExtension::resolveQuery((cPacket*) msg);
                receivedQueries++;

                cPacket *pk = check_and_cast<cPacket *>(msg);
                UDPDataIndication *ctrl = check_and_cast<UDPDataIndication *>(pk->getControlInfo());
                IPvXAddress srcAddress = ctrl->getSrcAddr();
                query->src_address = srcAddress.str();
                response = handleQuery(query);

                if (response == NULL)
                { // only happens if recursive resolving was initiated
                    delete msg;
                    return;
                }

                // free the query
                delete query;
                // and send the response to the source address
                sendResponse(response, srcAddress);
            }
            else
            {
                // Just got a response, lets see if its an answer fitting one of
                // the queries we need to resolved.
                response = handleRecursion((DNSPacket*) msg);

                if (response != NULL)
                {
                    // this was the final answer, i.e.
                    // get the original packet and the src addr
                    int id = ((DNSPacket*) msg)->getId();
                    CachedQuery* cq = (CachedQuery*) get_query_from_cache(id);

                    IPvXAddress addr = IPvXAddressResolver().resolve(cq->query->src_address.c_str());

                    // free cached query data
                    remove_query_from_cache(id, cq);

                    // we're not an authority, set it here.
                    sendResponse(response, addr);
                }

            }
        }

    }

    delete msg;

}

DNSPacket* DNSServerBase::handleRecursion(DNSPacket* packet)
{
    // first check if we have a query id that belongs to this packet
    // and the answer relates to the query

    DNSPacket* response;

    if (!queryCache.count(packet->getId()))
    {
        return NULL; // we do not have a query that belongs to this key
    }

    CachedQuery* cq = (CachedQuery*) queryCache[packet->getId()];
    ODnsExtension::Query* original_query = cq->query;

    // first check, see if there are actually answers

    if (DNS_HEADER_AA(packet->getOptions()) && packet->getAncount() > 0)
    {
        // we have what we looked for, return
        std::string msg_name = std::string("dns_response#") + std::to_string(original_query->id);
        response = ODnsExtension::createResponse(msg_name, 1, packet->getAncount(), packet->getNscount(),
                packet->getArcount(), original_query->id, DNS_HEADER_OPCODE(original_query->options), 0,
                DNS_HEADER_RD(original_query->options), 1, 0);

        short i;
        for (i = 0; i < cq->query->qdcount; i++)
        {
            ODnsExtension::appendQuestion(response, ODnsExtension::copyDnsQuestion(&cq->query->questions[i]), i);
        }

        std::string bubble_popup = "";
        for (i = 0; i < packet->getAncount(); i++)
        {

            // store the response in the cache
            if (responseCache)
            {
                // check if the record is not an A or AAAA record
                if (packet->getAnswers(i).rtype != DNS_TYPE_VALUE_A
                        && packet->getAnswers(i).rtype != DNS_TYPE_VALUE_AAAA)
                {
                    //create a copy and put it into the cache
                    DNSRecord* r = ODnsExtension::copyDnsRecord(&(packet->getAnswers(i)));

                    // put the record into the cache
                    bubble_popup.append("New cache entry:\n");
                    bubble_popup.append(r->rname.c_str());
                    bubble_popup.append(":");
                    bubble_popup.append(ODnsExtension::getTypeStringForValue(r->rtype));
                    bubble_popup.append(":");
                    bubble_popup.append(ODnsExtension::getClassStringForValue(r->rclass));
                    bubble_popup.append("\nData: ");
                    bubble_popup.append(r->strdata.c_str());
                    bubble_popup.append("\n---------\n");
                    responseCache->put_into_cache(r);
                }
            }

            ODnsExtension::appendAnswer(response, ODnsExtension::copyDnsRecord(&packet->getAnswers(i)), i);
        }

        if (bubble_popup != "")
        {
            EV << bubble_popup.c_str();
            this->getParentModule()->bubble(bubble_popup.c_str());
        }

        if (responseCache && original_query->questions[0].qname == packet->getQuestions(0).qname)
        {
            // we have a mismatch in the queries, this means we followed a CNAME chain
            // and used the end of chain to query the server, hence we need to append
            // the CNAME chain

            std::string cnhash = original_query->questions[0].qname + ":" + DNS_TYPE_STR_CNAME + ":" +
                    DNS_CLASS_STR_IN;
            std::list<std::string> hashes = responseCache->get_matching_hashes(cnhash);

            int num_hashes = hashes.size();
            // reset size of answers to ancount + hashes length
            response->setNumAnswers(response->getAncount() + num_hashes);
            response->setAncount(response->getAncount() + num_hashes);

            int pos = packet->getAncount();
            for(auto it = hashes.begin(); it != hashes.end(); it++)
            {
                // use the hash to get the corresponding entry
                std::string tmp = (std::string) *it;
                std::list<DNSRecord*> records = responseCache->get_from_cache(tmp);

                if (!records.empty())
                    break;

                // list should not be greater one otherwise there is a collision
                if (records.size() > 1)
                {
                    responseCache->remove_from_cache(tmp);
                    break;
                }

                // only one record, extract data into tmp
                if (((DNSRecord*) *(records.begin()))->rtype == DNS_TYPE_VALUE_CNAME)
                {
                    // append record to the section
                    ODnsExtension::appendAnswer(response, ODnsExtension::copyDnsRecord(((DNSRecord*) *(records.begin()))),
                            pos);
                    pos++;
                }
            }
        }

        for (i = 0; i < packet->getNscount(); i++)
        {
            ODnsExtension::appendAuthority(response, ODnsExtension::copyDnsRecord(&packet->getAuthorities(i)), i);
        }
        for (i = 0; i < packet->getArcount(); i++)
        {
            ODnsExtension::appendAdditional(response, ODnsExtension::copyDnsRecord(&packet->getAdditional(i)), i);
        }

        return response;
    }
    else if (DNS_HEADER_AA(packet->getOptions()) && packet->getAncount() == 0)
    {
        // return the entry not found response
        std::string msg_name = "dns_response#" + std::to_string(original_query->id);

        response = ODnsExtension::createResponse(msg_name, 1, 0, 0, 0, original_query->id,
                DNS_HEADER_OPCODE(original_query->options), 1, DNS_HEADER_RD(original_query->options), 1, 3);

        for (int i = 0; i < cq->query->qdcount; i++)
        {
            ODnsExtension::appendQuestion(response, ODnsExtension::copyDnsQuestion(&cq->query->questions[i]), i);
        }

        return response; // return the response with no entry found..
    }
    else if (packet->getNscount() > 0 && packet->getArcount() > 0 && !DNS_HEADER_AA(packet->getOptions()))
    {
        // we have an answer for a query
        // pick one at random and delegate the question

        int p = intrand(packet->getNscount());
        DNSRecord *r = &packet->getAdditional(p);

        // query the name server for our original query
        std::string msg_name = "dns_query#" + std::to_string(cq->internal_id) + std::string("--recursive");
        DNSPacket *query = ODnsExtension::createQuery(msg_name, packet->getQuestions(0).qname, DNS_CLASS_IN,
                packet->getQuestions(0).qtype, cq->internal_id, 1);

        // Resolve the ip address for the record
        IPvXAddress address = IPvXAddressResolver().resolve(r->strdata.c_str());

        if (!address.isUnspecified())
            sendResponse(query, address);

        return NULL; // since this packet is fine we pass it upwards
    }
    else if (packet->getNscount() > 0 && !DNS_HEADER_AA(packet->getOptions()))
    {
        // TODO: no ar record, we need to start at the beginning with this reference..
        return NULL;
    }
    else
    {
        // something went wrong, return a server failure query
        std::string msg_name = "dns_response#" + std::to_string(original_query->id);
        response = ODnsExtension::createResponse(msg_name, 1, 0, 0, 0, original_query->id,
                DNS_HEADER_OPCODE(original_query->options), 0, DNS_HEADER_RD(original_query->options), 1, 2);

        return response; // return the response with no entry found..
    }

    return NULL;
}

int DNSServerBase::remove_query_from_cache(int id, CachedQuery* cq)
{
    queryCache.erase(id);
    delete cq;
    return 1;
}

CachedQuery* DNSServerBase::get_query_from_cache(int id)
{
    CachedQuery* q = (CachedQuery*) queryCache[id];
    return q;
}

int DNSServerBase::store_in_query_cache(int id, ODnsExtension::Query* query)
{
    // store the query in the cache...

    CachedQuery* q = new CachedQuery();
    q->internal_id = id;
    q->query = query;

    queryCache[id] = q;
    return 1;
}

DNSPacket* DNSServerBase::handleQuery(ODnsExtension::Query* query)
{
    return NULL;
}

void DNSServerBase::sendResponse(DNSPacket *response, IPvXAddress returnAddress)
{
    if (!returnAddress.isUnspecified())
    {
        if (response == NULL)
        {
            std::cout << "Bad response\n" << std::endl;
            return;
        }

        response->setByteLength(ODnsExtension::estimateDnsPacketSize(response));

        out.sendTo(response, returnAddress, DNS_PORT);
    }
    else
        std::cout << "Missing return address\n" << std::endl;
}

DNSPacket* DNSServerBase::unsupportedOperation(ODnsExtension::Query *q)
{
    // TODO: return unsupported packet.
    return NULL;
}
