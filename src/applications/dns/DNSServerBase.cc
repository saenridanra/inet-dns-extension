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
        //in.setOutputGate(gate("udpIn"));
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
                query->src_address = g_strdup(srcAddress.str().c_str());
                response = handleQuery(query);

                if (response == NULL)
                { // only happens if recursive resolving was initiated
                    delete msg;
                    return;
                }

                /*g_printf(
                 "\n[%s]:\t\t Responding with answer for query [%s] \n",
                 this->getFullName(), ((DNSPacket*) msg)->getQuestions(0).qname);
                 for (int i = 0; i < response->getAncount(); i++) {
                 g_printf("\t\t [Answer]: %s | %s\n",
                 response->getAnswers(i).rname,
                 response->getAnswers(i).rdata);
                 }
                 for (int i = 0; i < response->getNscount(); i++) {
                 g_printf("\t\t [Answer]: %s | %s\n",
                 response->getAuthorities(i).rname,
                 response->getAuthorities(i).rdata);
                 }
                 for (int i = 0; i < response->getArcount(); i++) {
                 g_printf("\t\t [Answer]: %s | %s\n",
                 response->getAdditional(i).rname,
                 response->getAdditional(i).rdata);
                }*/

                // free the query
                g_free(query->src_address);
                free(query);
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

                    IPvXAddress addr = IPvXAddressResolver().resolve(cq->query->src_address);

                    /*g_printf(
                     "\n[%s]:\t\t Responding with answer for query [%s] \n",
                     this->getFullName(), ((DNSPacket*) msg)->getQuestions(0).qname);
                     for (int i = 0; i < response->getAncount(); i++) {
                     g_printf("\t\t [Answer]: %s | %s\n",
                     response->getAnswers(i).rname,
                     response->getAnswers(i).rdata);
                     }
                     for (int i = 0; i < response->getNscount(); i++) {
                     g_printf("\t\t [Answer]: %s | %s\n",
                     response->getAuthorities(i).rname,
                     response->getAuthorities(i).rdata);
                     }
                     for (int i = 0; i < response->getArcount(); i++) {
                     g_printf("\t\t [Answer]: %s | %s\n",
                     response->getAdditional(i).rname,
                     response->getAdditional(i).rdata);
                    }*/

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
    uint32_t *key = (uint32_t*) malloc(sizeof(uint32_t));
    *key = (uint32_t) packet->getId();

    if (!g_hash_table_contains(queryCache, key))
    {
        return NULL; // we do not have a query that belongs to this key
    }

    CachedQuery* cq = (CachedQuery*) g_hash_table_lookup(queryCache, key);
    ODnsExtension::Query* original_query = cq->query;
    free(key);

    // first check, see if there are actually answers

    /*g_printf("[%s]:\t\t Received response for query [%s]\n",
            this->getFullName(), packet->getQuestions(0).qname);*/

    if (DNS_HEADER_AA(packet->getOptions()) && packet->getAncount() > 0)
    {
        // we have what we looked for, return

        //g_printf("[%s]:\t\t Received desired response [%s] \n",
        //        this->getFullName(), original_query->getQuestions(0).qname);
        char *msg_name = g_strdup_printf("dns_response#%d", original_query->id);
        response = ODnsExtension::createResponse(msg_name, 1, packet->getAncount(), packet->getNscount(),
                packet->getArcount(), original_query->id, DNS_HEADER_OPCODE(original_query->options), 0,
                DNS_HEADER_RD(original_query->options), 1, 0);

        short i;
        for (i = 0; i < cq->query->qdcount; i++)
        {
            ODnsExtension::appendQuestion(response, ODnsExtension::copyDnsQuestion(&cq->query->questions[i]), i);
        }
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
                    responseCache->put_into_cache(r);
                }
            }

            ODnsExtension::appendAnswer(response, ODnsExtension::copyDnsRecord(&packet->getAnswers(i)), i);
        }

        if(responseCache && g_strcmp0(original_query->questions[0].qname, packet->getQuestions(0).qname)){
            // we have a mismatch in the queries, this means we followed a CNAME chain
            // and used the end of chain to query the server, hence we need to append
            // the CNAME chain

            char* cnhash = g_strdup_printf("%s:%s:%s", original_query->questions[0].qname, DNS_TYPE_STR_CNAME, DNS_CLASS_STR_IN);
            GList* hashes = responseCache->get_matching_hashes(cnhash);

            int num_hashes = g_list_length(hashes);
            // reset size of answers to ancount + hashes length
            response->setNumAnswers(response->getAncount() + num_hashes);
            response->setAncount(response->getAncount() + num_hashes);

            hashes = g_list_first(hashes);
            int pos = packet->getAncount();
            while(hashes){
                // use the hash to get the corresponding entry
                char* tmp = (char*) hashes->data;
                GList* records = NULL;
                records = responseCache->get_from_cache(tmp);

                if(!records)
                    break;

                // list should not be greater one otherwise there is a collision
                if(g_list_next(records)){
                    responseCache->remove_from_cache(tmp);
                    break;
                }

                // only one record, extract data into tmp
                if(((DNSRecord*) records->data)->rtype == DNS_TYPE_VALUE_CNAME){
                    // append record to the section
                    ODnsExtension::appendAnswer(response, ODnsExtension::copyDnsRecord(((DNSRecord*) records->data)), pos);
                    pos++;
                }

                hashes = g_list_next(hashes);
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
        char *msg_name = g_strdup_printf("dns_response#%d", original_query->id);

        /*g_printf("[%s]:\t\t Entry not found [%s] \n", this->getFullName(),
                packet->getQuestions(0).qname);*/

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

        //g_printf("[%s]:\t\t Delegating query [%s] to: [%s][%s]\n",
        //       this->getFullName(), original_query->getQuestions(0).qname,
        //        r->rname, r->rdata);

        // query the name server for our original query
        char *msg_name = g_strdup_printf("dns_query#%d--recursive", cq->internal_id);
        DNSPacket *query = ODnsExtension::createQuery(msg_name, packet->getQuestions(0).qname, DNS_CLASS_IN,
                packet->getQuestions(0).qtype, cq->internal_id, 1);

        // Resolve the ip address for the record
        IPvXAddress address = IPvXAddressResolver().resolve(r->rdata);

        if (!address.isUnspecified())
            out.sendTo(query, address, DNS_PORT);

        return NULL; // since this packet is fine we pass it upwards
    }
    else if (packet->getNscount() > 0 && !DNS_HEADER_AA(packet->getOptions()))
    {
        // TODO: no ar record, we need to start at the beginning with this reference..
        //g_printf("[%s]:\t\t No AR Record [%s] \n", this->getFullName(),
        //        original_query->getQuestions(0).qname);
        return NULL;
    }
    else
    {
        // something went wrong, return a server failure query
        char *msg_name = g_strdup_printf("dns_response#%d", original_query->id);

        //g_printf("[%s]:\t\t No answer for query [%s] \n", this->getFullName(),
        //        original_query->getQuestions(0).qname);
        response = ODnsExtension::createResponse(msg_name, 1, 0, 0, 0, original_query->id,
                DNS_HEADER_OPCODE(original_query->options), 0, DNS_HEADER_RD(original_query->options), 1, 2);

        return response; // return the response with no entry found..
    }

    return NULL;
}

int DNSServerBase::remove_query_from_cache(int id, CachedQuery* cq)
{
    g_hash_table_remove(queryCache, &id);
    g_free(cq->query->src_address);
    free(cq->query);
    free(cq);
    return 1;
}

CachedQuery* DNSServerBase::get_query_from_cache(int id)
{
    CachedQuery* q = (CachedQuery*) g_hash_table_lookup(queryCache, &id);
    return q;
}

int DNSServerBase::store_in_query_cache(int id, ODnsExtension::Query* query)
{
    // store the query in the cache...
    uint32_t* key = (uint32_t*) malloc(sizeof(uint32_t));
    *key = id;

    CachedQuery* q = (CachedQuery*) malloc(sizeof(*q));
    q->internal_id = id;
    q->query = query;

    g_hash_table_insert(queryCache, key, q);
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
        if(response == NULL){
            g_print("Bad response\n");
            return;
        }
        out.sendTo(response, returnAddress, DNS_PORT);
    }
    else
        g_print("Missing return address\n");
}

DNSPacket* DNSServerBase::unsupportedOperation(ODnsExtension::Query *q)
{
// TODO: return unsupported packet.
    return NULL;
}
