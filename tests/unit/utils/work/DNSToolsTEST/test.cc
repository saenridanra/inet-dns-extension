
#include <omnetpp.h>

#include "DNS.h"
#include "DNSTools.h"



namespace DNSToolsTEST {




class Test : public cSimpleModule
{
    public:
        Test() : cSimpleModule(32768) {}
        virtual void activity();
};

Define_Module(Test);

void Test::activity()
{

// create a number of fragmented datagrams
DNSPacket *q = new DNSPacket("test_packet_1");

if(!ODnsExtension::isDNSpacket(q)){
    return;
}

// Set id and options in header ..
q->setId(12345);
q->setQdcount(1);
q->setAncount(1);
q->setNscount(1);
q->setArcount(1);

unsigned short options = 0;
// QR and OPCODE already 0..
// Recursion desired ..
DNS_HEADER_SET_RD(options, 0);

// Setup question
q->setNumQuestions(1);

ODnsExtension::DNSQuestion question;
question.qname = "unassigned.buffalo.net";
question.qclass = 0;
question.qtype = 0;
q->setQuestions(0, question);


// Now check if resolveQuery works:

ODnsExtension::Query* resolveQuery = ODnsExtension::resolveQuery(q);

// output some data
ev << "query id: " << resolveQuery->id << "\n";


}

}; //namespace
