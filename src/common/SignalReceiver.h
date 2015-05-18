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

#ifndef SIGNALRECEIVER_H_
#define SIGNALRECEIVER_H_

#include <unordered_map>
#include <memory>
#include <string.h>

/**
 * @brief This interface class provides a generic way for a module to receive signals from none OMNeT++ modules.
 */
class SignalReceiver
{
    public:
        SignalReceiver();
        virtual ~SignalReceiver();

        /**
         * @brief Pass a signal with parameters to the receiver
         *
         * @param parMap Map of flags
         * @param additionalPayload it may be necessary to pass a pointer to a cPacket or other types
         */
        virtual void receiveSignal(std::unordered_map<std::string, int> parMap, void* additionalPayload) = 0;
};

#endif /* SIGNALRECEIVER_H_ */
