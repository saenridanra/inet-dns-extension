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

#include <DNSClientTraffGen.h>

Define_Module(DNSClientTraffGen);

DNSClientTraffGen::DNSClientTraffGen(){
    timeoutMsg = NULL;
}

DNSClientTraffGen::~DNSClientTraffGen(){
    cancelAndDelete(timeoutMsg);
}

void DNSClientTraffGen::initialize(int stage) {
    DNSClient::initialize(stage);
    std::cout << "\nDNSClientTraffGen: Stage --> " << stage << std::endl;
    if(stage == 0){
        time_to_send = par("time_to_send").doubleValue();
        qcount = 0;
        timeoutMsg = new cMessage("timer");

        init_hostnames();
        scheduleAt(simTime() + time_to_send, timeoutMsg);
    }
}

void DNSClientTraffGen::handleMessage(cMessage *msg) {
    if (msg->isSelfMessage()){
        handleTimer(msg);

        // no need to let the DNSClient handle the message
        return;
    }
    DNSClient::handleMessage(msg);

    delete(msg);
}

void DNSClientTraffGen::handleTimer(cMessage *msg){
    // Generate message for arbitrary hostname (randomly chosen), resolve it using the DNSClient
    scheduleAt(simTime() + time_to_send, timeoutMsg);
    int p = intrand(host_names.size());

    // choose the dns name, resolve using DNSClient
    std::string host_name = host_names[p];
    std::string type = types[p];
    int _type = ODnsExtension::getTypeValueForString(type);
    if(_type == -1){
        cRuntimeError("Malformated hostname_file with unknown type.");
    }

    int id = DNSClient::resolve(host_name, _type, 1, &DNSClientTraffGen::callback, -1, this);
    // TODO: remember id, for now just ignore
    // we can only do something ones the server is implemented

    if(id == -1){
        // already in the cache
        IPvXAddress* address = DNSClient::getAddressFromCache(host_name);
    }

    qcount++;

}

void DNSClientTraffGen::init_hostnames()
{
    std::string line;

    std::fstream hostFile(par("hostname_file").stringValue(), std::ios::in);
    while(getline(hostFile, line, '\n'))
    {
        if (line.empty() || line[0] == '#')
            continue;

        // use a tokenizer to interpret the line
        std::vector<std::string> tokens = cStringTokenizer(line.c_str()).asVector();
        types.push_back(tokens[0]);
        host_names.push_back(tokens[1]);
    }
}

void DNSClientTraffGen::handleResponse(int id){
    // emit some statistics, the response should be in the cache already..


}

void DNSClientTraffGen::callback(int id, void * this_pointer){
    DNSClientTraffGen * self = static_cast<DNSClientTraffGen*>(this_pointer);
    self->handleResponse(id);
}

void DNSClientTraffGen::finish(){
    // TODO: write some statistics
    out.close();
}
