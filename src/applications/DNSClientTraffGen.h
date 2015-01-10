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

#ifndef DNSCLIENTTRAFFGEN_H_
#define DNSCLIENTTRAFFGEN_H_

#include <omnetpp.h>
#include <DNSClient.h>
#include <fstream>
#include <vector>
#include <string.h>

class DNSClientTraffGen : public DNSClient {

public:
    int qcount;
    simtime_t time_to_send;
    cMessage* timeoutMsg;

    std::vector<std::string> host_names;
    std::vector<std::string> types;

protected:
    virtual void initialize(int stage);
    virtual int numInitStages() const { return 4; }
    virtual void handleMessage(cMessage *msg);
    virtual void finish();
    virtual void handleTimer(cMessage *msg);

    virtual void handleResponse(int id);
    static void callback(int id, void * this_pointer);
    virtual void init_hostnames();

public:
    DNSClientTraffGen();
    virtual ~DNSClientTraffGen();
};

#endif /* DNSCLIENTTRAFFGEN_H_ */
