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
#include <iostream>
#include <vector>
#include <string.h>

/**
 * @brief @ref DNSClientTraffGen randomly generates DNS traffic
 *
 * , based on query provided in a file called host_names,
 * which needs to be provided as a parameter in the ned definition
 * to the client node.
 *
 * @author Andreas Rain, Distributed Systems Group, University of Konstanz
 * @date March 26, 2015
 */
class DNSClientTraffGen : public DNSClient {

public:
    /**
     * @brief Running query counter.
     */
    int qcount;

    /**
     * @brief Time between generated queries.
     */
    simtime_t time_to_send;

    /**
     * @brief A self scheduled timeout message.
     */
    cMessage* timeoutMsg;

    /**
     * @brief The hostnames which are used for random queries.
     */
    std::vector<std::string> host_names;

    /**
     * @brief Additionally, the type (A, AAAA) can be specified.
     */
    std::vector<std::string> types;

protected:
    virtual void initialize(int stage);
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void handleMessage(cMessage *msg);
    virtual void finish();
    virtual void handleTimer(cMessage *msg);

    /**
     * @brief Handles a response based on the id.
     *
     * @param id Reference id for the cache.
     */
    virtual void handleResponse(int id);

    /**
     * @brief callback function, called when response is received.
     *
     * @param id Reference id for the query.
     * @param this_pointer Pointer to the calling class.
     */
    static void callback(int id, void * this_pointer);

    /**
     * @brief Initializes the hostnames and types for random traffic generation.
     */
    virtual void init_hostnames();

public:
    DNSClientTraffGen();
    virtual ~DNSClientTraffGen();
};

#endif /* DNSCLIENTTRAFFGEN_H_ */
