#
# OMNeT++/OMNEST Makefile for libopp_dns_extension
#
# This file was generated with the command:
#  opp_makemake -f --deep --make-so -I/usr/include/glib-2.0 -I/home/saen/master-project/workspaces/omnetpp/inet/src/transport/tcp_common -I/home/saen/master-project/workspaces/omnetpp/inet/src/base -I/home/saen/master-project/workspaces/omnetpp/inet/src/util -I/home/saen/master-project/workspaces/omnetpp/inet/src/linklayer/ieee80211/mac -I/home/saen/master-project/workspaces/omnetpp/inet/src/transport/udp -I/home/saen/master-project/workspaces/omnetpp/inet/src/linklayer/ieee80211/radio/errormodel -I/home/saen/master-project/workspaces/omnetpp/inet/src/util/headerserializers -I/home/saen/master-project/workspaces/omnetpp/inet/src/linklayer/ieee80211/radio -I/home/saen/master-project/workspaces/omnetpp/inet/src/status -I/home/saen/master-project/workspaces/omnetpp/inet/src/transport/sctp -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/icmpv6 -I/home/saen/master-project/workspaces/omnetpp/inet/src/linklayer/radio/propagation -I/home/saen/master-project/workspaces/omnetpp/inet/src/transport/contract -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/ipv6tunneling -I/home/saen/master-project/workspaces/omnetpp/inet/src/world/radio -I/home/saen/master-project/workspaces/omnetpp/inet/src/linklayer/contract -I/home/saen/master-project/workspaces/omnetpp/inet/src/util/headerserializers/udp -I/home/saen/master-project/workspaces/omnetpp/inet/src/util/headerserializers/tcp -I/home/saen/master-project/workspaces/omnetpp/inet/src/linklayer/radio -I/home/saen/master-project/workspaces/omnetpp/inet/src/world/obstacles -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/common -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/ipv6 -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/arp -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/routing/aodv -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/contract -I/home/saen/master-project/workspaces/omnetpp/inet/src -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/xmipv6 -I/home/saen/master-project/workspaces/omnetpp/inet/src/util/headerserializers/sctp -I/home/saen/master-project/workspaces/omnetpp/inet/src/util/headerserializers/ipv6 -I/home/saen/master-project/workspaces/omnetpp/inet/src/battery/models -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/autorouting/ipv4 -I/home/saen/master-project/workspaces/omnetpp/inet/src/networklayer/ipv4 -I/home/saen/master-project/workspaces/omnetpp/inet/src/mobility/contract -I/home/saen/master-project/workspaces/omnetpp/inet/src/applications/pingapp -I/home/saen/master-project/workspaces/omnetpp/inet/src/linklayer/common -I/home/saen/master-project/workspaces/omnetpp/inet/src/util/headerserializers/ipv4 -L/home/saen/master-project/workspaces/omnetpp/inet/out/$$\(CONFIGNAME\)/src -linet -DINET_IMPORT -KINET_PROJ=/home/saen/master-project/workspaces/omnetpp/inet
#

# Name of target to be created (-o option)
TARGET = libopp_dns_extension$(SHARED_LIB_SUFFIX)

# C++ include paths (with -I)
INCLUDE_PATH = \
    -I/usr/include/glib-2.0 \
    -I$(INET_PROJ)/src/transport/tcp_common \
    -I$(INET_PROJ)/src/base \
    -I$(INET_PROJ)/src/util \
    -I$(INET_PROJ)/src/linklayer/ieee80211/mac \
    -I$(INET_PROJ)/src/transport/udp \
    -I$(INET_PROJ)/src/linklayer/ieee80211/radio/errormodel \
    -I$(INET_PROJ)/src/util/headerserializers \
    -I$(INET_PROJ)/src/linklayer/ieee80211/radio \
    -I$(INET_PROJ)/src/status \
    -I$(INET_PROJ)/src/transport/sctp \
    -I$(INET_PROJ)/src/networklayer/icmpv6 \
    -I$(INET_PROJ)/src/linklayer/radio/propagation \
    -I$(INET_PROJ)/src/transport/contract \
    -I$(INET_PROJ)/src/networklayer/ipv6tunneling \
    -I$(INET_PROJ)/src/world/radio \
    -I$(INET_PROJ)/src/linklayer/contract \
    -I$(INET_PROJ)/src/util/headerserializers/udp \
    -I$(INET_PROJ)/src/util/headerserializers/tcp \
    -I$(INET_PROJ)/src/linklayer/radio \
    -I$(INET_PROJ)/src/world/obstacles \
    -I$(INET_PROJ)/src/networklayer/common \
    -I$(INET_PROJ)/src/networklayer/ipv6 \
    -I$(INET_PROJ)/src/networklayer/arp \
    -I$(INET_PROJ)/src/networklayer/routing/aodv \
    -I$(INET_PROJ)/src/networklayer/contract \
    -I$(INET_PROJ)/src \
    -I$(INET_PROJ)/src/networklayer/xmipv6 \
    -I$(INET_PROJ)/src/util/headerserializers/sctp \
    -I$(INET_PROJ)/src/util/headerserializers/ipv6 \
    -I$(INET_PROJ)/src/battery/models \
    -I$(INET_PROJ)/src/networklayer/autorouting/ipv4 \
    -I$(INET_PROJ)/src/networklayer/ipv4 \
    -I$(INET_PROJ)/src/mobility/contract \
    -I$(INET_PROJ)/src/applications/pingapp \
    -I$(INET_PROJ)/src/linklayer/common \
    -I$(INET_PROJ)/src/util/headerserializers/ipv4 \
    -I. \
    -Iapplications \
    -Iapplications/dns \
    -Icommon \
    -Imessages \
    -Inetworks \
    -Inetworks/complex_dns_network \
    -Inetworks/complex_dns_network/results \
    -Inetworks/complex_dns_network/subnets \
    -Inetworks/results \
    -Iutils

# Additional object and library files to link with
EXTRA_OBJS =

# Additional libraries (-L, -l options)
LIBS = -L$(INET_PROJ)/out/$(CONFIGNAME)/src  -linet
LIBS += -Wl,-rpath,`abspath $(INET_PROJ)/out/$(CONFIGNAME)/src`

# Output directory
PROJECT_OUTPUT_DIR = ../out
PROJECTRELATIVE_PATH = src
O = $(PROJECT_OUTPUT_DIR)/$(CONFIGNAME)/$(PROJECTRELATIVE_PATH)

# Object files for local .cc and .msg files
OBJS = \
    $O/applications/dns/DNSAuthServer.o \
    $O/applications/dns/DNSClientTraffGen.o \
    $O/applications/dns/DNSClient.o \
    $O/applications/dns/DNSServerBase.o \
    $O/common/DNSSimpleCache.o \
    $O/common/DNSCache.o \
    $O/utils/DNSTools.o \
    $O/utils/DNSZoneConfig.o \
    $O/messages/DNSPacket_m.o

# Message files
MSGFILES = \
    messages/DNSPacket.msg

# Other makefile variables (-K)
INET_PROJ=/home/saen/master-project/workspaces/omnetpp/inet

#------------------------------------------------------------------------------

# Pull in OMNeT++ configuration (Makefile.inc or configuser.vc)

ifneq ("$(OMNETPP_CONFIGFILE)","")
CONFIGFILE = $(OMNETPP_CONFIGFILE)
else
ifneq ("$(OMNETPP_ROOT)","")
CONFIGFILE = $(OMNETPP_ROOT)/Makefile.inc
else
CONFIGFILE = $(shell opp_configfilepath)
endif
endif

ifeq ("$(wildcard $(CONFIGFILE))","")
$(error Config file '$(CONFIGFILE)' does not exist -- add the OMNeT++ bin directory to the path so that opp_configfilepath can be found, or set the OMNETPP_CONFIGFILE variable to point to Makefile.inc)
endif

include $(CONFIGFILE)

# Simulation kernel and user interface libraries
OMNETPP_LIB_SUBDIR = $(OMNETPP_LIB_DIR)/$(TOOLCHAIN_NAME)
OMNETPP_LIBS = -L"$(OMNETPP_LIB_SUBDIR)" -L"$(OMNETPP_LIB_DIR)" -loppenvir$D $(KERNEL_LIBS) $(SYS_LIBS)

COPTS = $(CFLAGS) -DINET_IMPORT $(INCLUDE_PATH) -I$(OMNETPP_INCL_DIR)
MSGCOPTS = $(INCLUDE_PATH)

# we want to recompile everything if COPTS changes,
# so we store COPTS into $COPTS_FILE and have object
# files depend on it (except when "make depend" was called)
COPTS_FILE = $O/.last-copts
ifneq ($(MAKECMDGOALS),depend)
ifneq ("$(COPTS)","$(shell cat $(COPTS_FILE) 2>/dev/null || echo '')")
$(shell $(MKPATH) "$O" && echo "$(COPTS)" >$(COPTS_FILE))
endif
endif

#------------------------------------------------------------------------------
# User-supplied makefile fragment(s)
# >>>
# inserted from file 'makefrag':
LIBS+=$(shell pkg-config --libs glib-2.0)
CFLAGS+=$(shell pkg-config --cflags glib-2.0) -DDEBUG_ENABLED
CXXFLAGS+=$(shell pkg-config --cflags glib-2.0) -DDEBUG_ENABLED

# <<<
#------------------------------------------------------------------------------

# Main target
all: $O/$(TARGET)
	$(Q)$(LN) $O/$(TARGET) .

$O/$(TARGET): $(OBJS)  $(wildcard $(EXTRA_OBJS)) Makefile
	@$(MKPATH) $O
	@echo Creating shared library: $@
	$(Q)$(SHLIB_LD) -o $O/$(TARGET)  $(OBJS) $(EXTRA_OBJS) $(AS_NEEDED_OFF) $(WHOLE_ARCHIVE_ON) $(LIBS) $(WHOLE_ARCHIVE_OFF) $(OMNETPP_LIBS) $(LDFLAGS)
	$(Q)$(SHLIB_POSTPROCESS) $O/$(TARGET)

.PHONY: all clean cleanall depend msgheaders

.SUFFIXES: .cc

$O/%.o: %.cc $(COPTS_FILE)
	@$(MKPATH) $(dir $@)
	$(qecho) "$<"
	$(Q)$(CXX) -c $(CXXFLAGS) $(COPTS) -o $@ $<

%_m.cc %_m.h: %.msg
	$(qecho) MSGC: $<
	$(Q)$(MSGC) -s _m.cc $(MSGCOPTS) $?

msgheaders: $(MSGFILES:.msg=_m.h)

clean:
	$(qecho) Cleaning...
	$(Q)-rm -rf $O
	$(Q)-rm -f opp_dns_extension opp_dns_extension.exe libopp_dns_extension.so libopp_dns_extension.a libopp_dns_extension.dll libopp_dns_extension.dylib
	$(Q)-rm -f ./*_m.cc ./*_m.h
	$(Q)-rm -f applications/*_m.cc applications/*_m.h
	$(Q)-rm -f applications/dns/*_m.cc applications/dns/*_m.h
	$(Q)-rm -f common/*_m.cc common/*_m.h
	$(Q)-rm -f messages/*_m.cc messages/*_m.h
	$(Q)-rm -f networks/*_m.cc networks/*_m.h
	$(Q)-rm -f networks/complex_dns_network/*_m.cc networks/complex_dns_network/*_m.h
	$(Q)-rm -f networks/complex_dns_network/results/*_m.cc networks/complex_dns_network/results/*_m.h
	$(Q)-rm -f networks/complex_dns_network/subnets/*_m.cc networks/complex_dns_network/subnets/*_m.h
	$(Q)-rm -f networks/results/*_m.cc networks/results/*_m.h
	$(Q)-rm -f utils/*_m.cc utils/*_m.h

cleanall: clean
	$(Q)-rm -rf $(PROJECT_OUTPUT_DIR)

depend:
	$(qecho) Creating dependencies...
	$(Q)$(MAKEDEPEND) $(INCLUDE_PATH) -f Makefile -P\$$O/ -- $(MSG_CC_FILES)  ./*.cc applications/*.cc applications/dns/*.cc common/*.cc messages/*.cc networks/*.cc networks/complex_dns_network/*.cc networks/complex_dns_network/results/*.cc networks/complex_dns_network/subnets/*.cc networks/results/*.cc utils/*.cc

# DO NOT DELETE THIS LINE -- make depend depends on it.
$O/applications/dns/DNSAuthServer.o: applications/dns/DNSAuthServer.cc \
	$(INET_PROJ)/src/base/Compat.h \
	$(INET_PROJ)/src/base/INETDefs.h \
	$(INET_PROJ)/src/networklayer/contract/IPv4Address.h \
	$(INET_PROJ)/src/networklayer/contract/IPv6Address.h \
	$(INET_PROJ)/src/networklayer/contract/IPvXAddress.h \
	$(INET_PROJ)/src/networklayer/contract/IPvXAddressResolver.h \
	$(INET_PROJ)/src/transport/contract/UDPControlInfo_m.h \
	$(INET_PROJ)/src/transport/contract/UDPSocket.h \
	applications/dns/DNSAuthServer.h \
	applications/dns/DNSServerBase.h \
	common/DNS.h \
	messages/DNSPacket_m.h \
	utils/DNSTools.h \
	utils/DNSZoneConfig.h
$O/applications/dns/DNSClient.o: applications/dns/DNSClient.cc \
	$(INET_PROJ)/src/base/Compat.h \
	$(INET_PROJ)/src/base/INETDefs.h \
	$(INET_PROJ)/src/networklayer/contract/IPv4Address.h \
	$(INET_PROJ)/src/networklayer/contract/IPv6Address.h \
	$(INET_PROJ)/src/networklayer/contract/IPvXAddress.h \
	$(INET_PROJ)/src/networklayer/contract/IPvXAddressResolver.h \
	$(INET_PROJ)/src/transport/contract/UDPSocket.h \
	applications/dns/DNSClient.h \
	common/DNS.h \
	common/DNSCache.h \
	common/DNSSimpleCache.h \
	messages/DNSPacket_m.h \
	utils/DNSTools.h
$O/applications/dns/DNSClientTraffGen.o: applications/dns/DNSClientTraffGen.cc \
	$(INET_PROJ)/src/base/Compat.h \
	$(INET_PROJ)/src/base/INETDefs.h \
	$(INET_PROJ)/src/networklayer/contract/IPv4Address.h \
	$(INET_PROJ)/src/networklayer/contract/IPv6Address.h \
	$(INET_PROJ)/src/networklayer/contract/IPvXAddress.h \
	$(INET_PROJ)/src/networklayer/contract/IPvXAddressResolver.h \
	$(INET_PROJ)/src/transport/contract/UDPSocket.h \
	applications/dns/DNSClient.h \
	applications/dns/DNSClientTraffGen.h \
	common/DNS.h \
	common/DNSCache.h \
	common/DNSSimpleCache.h \
	messages/DNSPacket_m.h \
	utils/DNSTools.h
$O/applications/dns/DNSServerBase.o: applications/dns/DNSServerBase.cc \
	$(INET_PROJ)/src/base/Compat.h \
	$(INET_PROJ)/src/base/INETDefs.h \
	$(INET_PROJ)/src/networklayer/contract/IPv4Address.h \
	$(INET_PROJ)/src/networklayer/contract/IPv6Address.h \
	$(INET_PROJ)/src/networklayer/contract/IPvXAddress.h \
	$(INET_PROJ)/src/networklayer/contract/IPvXAddressResolver.h \
	$(INET_PROJ)/src/transport/contract/UDPControlInfo_m.h \
	$(INET_PROJ)/src/transport/contract/UDPSocket.h \
	applications/dns/DNSServerBase.h \
	common/DNS.h \
	messages/DNSPacket_m.h \
	utils/DNSTools.h
$O/common/DNSCache.o: common/DNSCache.cc \
	common/DNS.h \
	common/DNSCache.h \
	messages/DNSPacket_m.h \
	utils/DNSTools.h
$O/common/DNSSimpleCache.o: common/DNSSimpleCache.cc \
	common/DNS.h \
	common/DNSCache.h \
	common/DNSSimpleCache.h \
	messages/DNSPacket_m.h \
	utils/DNSTools.h
$O/messages/DNSPacket_m.o: messages/DNSPacket_m.cc \
	common/DNS.h \
	messages/DNSPacket_m.h
$O/utils/DNSTools.o: utils/DNSTools.cc \
	common/DNS.h \
	messages/DNSPacket_m.h \
	utils/DNSTools.h
$O/utils/DNSZoneConfig.o: utils/DNSZoneConfig.cc \
	utils/DNSZoneConfig.h

