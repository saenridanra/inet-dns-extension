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

        nameserver = par("nameserver").stdstringValue();
        nameserver_ip = par("nameserver_ip").stdstringValue();
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
    std::string ip, method, alias, qbase, alias_domain, echo_domain, msg_name;

    std::regex r_standard_query ("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.(cca)\\.((?:\\w|-)+)\\.(\\w+\\.\\w+\\.\\w+)");
    std::regex r_a_query ("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.(00)\\.(\\w+\\.\\w+\\.\\w+)");

    int num_an_records = 0, num_ns_records = 0, num_ar_records = 0, id, opcode, rd, ra;
    std::list<DNSRecord*> an_records;
    DNSPacket* response;

    // create string obj. matcher
    auto m = std::smatch{};

    // first analyze query according to stateless dns
    std::string qname = query->questions[0].qname; // lower case query

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
        //query
        if (std::regex_match(qname, m, r_standard_query)) {
            ip = m[1].str();
            method = m[2].str();
            alias = m[3].str();
            qbase = m[4].str();
            have_match = 1;
        }
        if (!have_match) {
            //query for echo domain A
            if (std::regex_match(qname, m, r_a_query)) {
                ip = m[1].str();
                method = m[2].str();
                qbase = m[3].str();
                alias = std::string("");
                have_match = 1;
            }
        }
    }

    msg_name = std::string("dns_response#") + std::to_string(response_count++);

    if (!have_match) {
        response = ODnsExtension::createResponse(msg_name, 1, num_an_records,
                num_ns_records, num_ar_records, id, opcode, 1, rd, ra, 0);
        appendQuestion(response, ODnsExtension::copyDnsQuestion(&query->questions[0]), 0);
        return response;
    }

    // generate answer, check method
    alias_domain = alias + std::string(".") + qbase;
    echo_domain = ip + std::string(".00.") + qbase;

    // basic methods for the simulation
    if (method == "00") {
        DNSRecord* r = new DNSRecord();
        r->strdata = ip;
        r->rname = qname;
        r->rclass = (short) DNS_CLASS_IN;
        r->rtype = (short) query->questions[0].qtype;
        r->rdlength = ip.length();
        r->ttl = 10000;

        num_an_records++;
        an_records.push_back(r);
    } else if (method == "cca") {
        // first cname RR
        DNSRecord* r = new DNSRecord();
        r->rname = qname;
        r->strdata = alias_domain;
        r->rclass = (short) DNS_CLASS_IN;
        r->rtype = DNS_TYPE_VALUE_CNAME;
        r->rdlength = alias_domain.length();
        r->ttl = 10000;

        num_an_records++;
        an_records.push_back(r);

        // second cname RR
        r = new DNSRecord();
        r->rname = alias_domain;
        r->strdata = echo_domain;
        r->rclass = (short) DNS_CLASS_IN;
        r->rtype = (short) DNS_TYPE_VALUE_CNAME;
        r->rdlength = echo_domain.length();
        r->ttl = 10000;

        num_an_records++;
        an_records.push_back(r);

        // A RR
        r = new DNSRecord();
        r->rname = echo_domain;
        r->strdata = ip;
        r->rclass = (short) DNS_CLASS_IN;
        r->rtype = (short) DNS_TYPE_VALUE_A;
        r->rdlength = ip.length();
        r->ttl = 10000;

        num_an_records++;
        an_records.push_back(r);
    }

    // create response packet, append question and answers

    response = ODnsExtension::createResponse(msg_name, 1, num_an_records,
            num_ns_records, num_ar_records, id, opcode, 1, rd, ra, 0);

    appendQuestion(response, ODnsExtension::copyDnsQuestion(&query->questions[0]), 0);

    int index = 0;

    for (auto it : an_records) {
        ODnsExtension::appendAnswer(response,
                it, index++);
    }

    // no auth or add records in this case, return the response

    return response;
}

void DNSEchoServer::sendResponse(DNSPacket *response,
        IPvXAddress returnAddress) {
    response->setByteLength(ODnsExtension::estimateDnsPacketSize(response));
    out.sendTo(response, returnAddress, DNS_PORT);
}

DNSPacket* DNSEchoServer::unsupportedOperation(ODnsExtension::Query *q) {
    // TODO: return unsupported packet.
    return NULL;
}
