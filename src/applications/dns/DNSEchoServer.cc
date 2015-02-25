//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#include "DNSEchoServer.h"

Define_Module(DNSEchoServer);

void DNSEchoServer::initialize(int stage) {
    if (stage == 0) {
        cSimpleModule::initialize(stage);
        // Initialize gates
        //in.setOutputGate(gate("udpIn"));
        out.setOutputGate(gate("udpOut"));
        out.bind(DNS_PORT);

        receivedQueries = 0;

        nameserver = par("nameserver").stringValue();
        nameserver_ip = par("nameserver_ip").stringValue();

        // compile regexes
        standard_query_regex = g_regex_new(standard_query, G_REGEX_CASELESS, G_REGEX_MATCH_NOTEMPTY, &regex_error);
        a_query_regex = g_regex_new(a_query, G_REGEX_CASELESS, G_REGEX_MATCH_NOTEMPTY, &regex_error);
    }
}

void DNSEchoServer::handleMessage(cMessage *msg) {
    int isDNS = 0;
    int isQR = 0;
    ODnsExtension::Query* query;
    DNSPacket* response;

    // Check if we received a query
    if (msg->arrivedOn("udpIn")) {
        if ((isDNS = ODnsExtension::isDNSpacket((cPacket*) msg))) {
            if ((isQR = ODnsExtension::isQueryOrResponse((cPacket*) msg))
                    == 0) {
                query = ODnsExtension::resolveQuery((cPacket*) msg);
                receivedQueries++;

                cPacket *pk = check_and_cast<cPacket *>(msg);
                UDPDataIndication *ctrl = check_and_cast<UDPDataIndication *>(
                        pk->getControlInfo());
                IPvXAddress srcAddress = ctrl->getSrcAddr();
                response = handleQuery(query);

                if (response == NULL) {
                    // only happens for unsupported operations in this case
                    delete msg;
                    return;
                }

                // and send the response to the source address
                sendResponse(response, srcAddress);
            } else {
                // Echo Servers don't handle responses , just drop it
            }
        }

    }

    delete msg;

}

DNSPacket* DNSEchoServer::handleQuery(ODnsExtension::Query* query) {
    int have_match = 0;
    char *ip, *method, *alias, *qbase, *alias_domain, *echo_domain, *msg_name;
    int num_an_records = 0, num_ns_records = 0, num_ar_records = 0, id, opcode, rd, ra;
    GList* an_records = NULL;
    DNSPacket* response;

    // first analyze query according to stateless dns
    char* qname = query->questions[0].qname; // lower case query

    // initializes options
    id = query->id;

    opcode = DNS_HEADER_OPCODE(query->options);
    // recursion desired?
    rd = DNS_HEADER_RD(query->options);
    // recursion available
    ra = DNS_HEADER_RA(query->options);

    // only supporting A queries for now
    // can easily be extended to other types using the reference
    // implementation of stateless dns
    if (query->questions[0].qtype == DNS_TYPE_VALUE_A) {
        g_regex_match(standard_query_regex, qname, g_regex_get_match_flags(standard_query_regex), &regex_match_info);

        //query
        if (g_match_info_matches(regex_match_info)) {
            ip = g_match_info_fetch(regex_match_info, 1);
            method = g_match_info_fetch(regex_match_info, 2);
            alias = g_match_info_fetch(regex_match_info, 3);
            qbase = g_match_info_fetch(regex_match_info, 4);
            have_match = 1;
        }
        if (!have_match) {
            g_regex_match(a_query_regex, qname, g_regex_get_match_flags(a_query_regex), &regex_match_info);
            //query for echo domain A
            if (g_match_info_matches(regex_match_info)) {
                ip = g_match_info_fetch(regex_match_info, 1);
                method = g_match_info_fetch(regex_match_info, 2);
                qbase = g_match_info_fetch(regex_match_info, 3);
                alias = "";
                have_match = 1;
            }
        }
    }

    msg_name = (char*) malloc(20);
    sprintf(msg_name, "dns_response#%d", response_count++);

    if (!have_match) {
        response = ODnsExtension::createResponse(msg_name, 1, num_an_records,
                num_ns_records, num_ar_records, id, opcode, 1, rd, ra, 0);
    }

    // generate answer, check method
    alias_domain = g_strdup_printf("%s.%s", alias, qbase);
    echo_domain = g_strdup_printf("%s.00.%s", ip, qbase);

    // basic methods for the simulation
    if (!g_strcmp0(method, "00")) {
        DNSRecord* r = (ODnsExtension::DNSRecord*) malloc(sizeof(*r));
        r->rdata = g_strdup(ip);
        r->rname = g_strdup(qname);
        r->rclass = (short) DNS_CLASS_IN;
        r->rtype = (short) query->questions[0].qtype;
        r->rdlength = strlen(r->rdata);
        r->ttl = 10000;

        num_an_records++;
        an_records = g_list_append(an_records, r);
    } else if (!g_strcmp0(method, "cca")) {
        // first cname RR
        DNSRecord* r = (ODnsExtension::DNSRecord*) malloc(sizeof(*r));
        r->rname = g_strdup(qname);
        r->rdata = g_strdup(alias_domain);
        r->rclass = (short) DNS_CLASS_IN;
        r->rtype = DNS_TYPE_VALUE_CNAME;
        r->rdlength = strlen(r->rdata);
        r->ttl = 10000;

        num_an_records++;
        an_records = g_list_append(an_records, r);

        // second cname RR
        r = (ODnsExtension::DNSRecord*) malloc(sizeof(*r));
        r->rname = g_strdup(alias_domain);
        r->rdata = g_strdup(echo_domain);
        r->rclass = (short) DNS_CLASS_IN;
        r->rtype = (short) DNS_TYPE_VALUE_CNAME;
        r->rdlength = strlen(r->rdata);
        r->ttl = 10000;

        num_an_records++;
        an_records = g_list_append(an_records, r);

        // A RR
        r = (ODnsExtension::DNSRecord*) malloc(sizeof(*r));
        r->rname = g_strdup(echo_domain);
        r->rdata = g_strdup(ip);
        r->rclass = (short) DNS_CLASS_IN;
        r->rtype = (short) DNS_TYPE_VALUE_A;
        r->rdlength = strlen(r->rdata);
        r->ttl = 10000;

        num_an_records++;
        an_records = g_list_append(an_records, r);
    }

    // create response packet, append question and answers

    response = ODnsExtension::createResponse(msg_name, 1, num_an_records,
            num_ns_records, num_ar_records, id, opcode, 1, rd, ra, 0);

    response->setQuestions(0, query->questions[0]);

    int index = 0;
    GList *next = g_list_first(an_records);

    if (an_records > 0) {
        while (next) {
            ODnsExtension::appendAnswer(response,
                    (ODnsExtension::DNSRecord*) next->data, index++);

            next = g_list_next(next);
        }
    }

    // no auth or add records in this case, return the response

    return response;
}

void DNSEchoServer::sendResponse(DNSPacket *response,
        IPvXAddress returnAddress) {
    out.sendTo(response, returnAddress, DNS_PORT);
}

DNSPacket* DNSEchoServer::unsupportedOperation(ODnsExtension::Query *q) {
    // TODO: return unsupported packet.
    return NULL;
}
