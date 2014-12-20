#
# OMNeT++/OMNEST Makefile for libopp_dns_extension
#
# This file was generated with the command:
#  opp_makemake -f -e cpp --deep -a
#

# Name of target to be created (-o option)
TARGET = libopp_dns_extension$(A_LIB_SUFFIX)

# C++ include paths (with -I)
INCLUDE_PATH = \
    -I. \
    -Ilib \
    -Isimulations \
    -Isrc \
    -Isrc/applications \
    -Isrc/common \
    -Isrc/messages \
    -Isrc/utils \
    -Itests \
    -Itests/unit \
    -Itests/unit/utils \
    -Itests/unit/utils/work \
    -Itests/unit/utils/work/DNSToolsTEST \
    -Itests/unit/utils/work/out \
    -Itests/unit/utils/work/out/gcc-debug \
    -Itests/unit/utils/work/out/gcc-debug/DNSToolsTEST

# Additional object and library files to link with
EXTRA_OBJS =

# Output directory
PROJECT_OUTPUT_DIR = out
PROJECTRELATIVE_PATH =
O = $(PROJECT_OUTPUT_DIR)/$(CONFIGNAME)/$(PROJECTRELATIVE_PATH)

# Object files for local .cpp and .msg files
OBJS = $O/src/utils/DNSTools.o $O/src/messages/DNSPacket_m.o

# Message files
MSGFILES = \
    src/messages/DNSPacket.msg

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

COPTS = $(CFLAGS)  $(INCLUDE_PATH) -I$(OMNETPP_INCL_DIR)
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
# <<<
#------------------------------------------------------------------------------

# Main target
all: $O/$(TARGET)
	$(Q)$(LN) $O/$(TARGET) .

$O/$(TARGET): $(OBJS)  $(wildcard $(EXTRA_OBJS)) Makefile
	@$(MKPATH) $O
	@echo Creating static library: $@
	$(Q)$(AR) $O/$(TARGET)  $(OBJS) $(EXTRA_OBJS)

.PHONY: all clean cleanall depend msgheaders

.SUFFIXES: .cpp

$O/%.o: %.cpp $(COPTS_FILE)
	@$(MKPATH) $(dir $@)
	$(qecho) "$<"
	$(Q)$(CXX) -c $(CXXFLAGS) $(COPTS) -o $@ $<

%_m.cpp %_m.h: %.msg
	$(qecho) MSGC: $<
	$(Q)$(MSGC) -s _m.cpp $(MSGCOPTS) $?

msgheaders: $(MSGFILES:.msg=_m.h)

clean:
	$(qecho) Cleaning...
	$(Q)-rm -rf $O
	$(Q)-rm -f opp_dns_extension opp_dns_extension.exe libopp_dns_extension.so libopp_dns_extension.a libopp_dns_extension.dll libopp_dns_extension.dylib
	$(Q)-rm -f ./*_m.cpp ./*_m.h
	$(Q)-rm -f lib/*_m.cpp lib/*_m.h
	$(Q)-rm -f simulations/*_m.cpp simulations/*_m.h
	$(Q)-rm -f src/*_m.cpp src/*_m.h
	$(Q)-rm -f src/applications/*_m.cpp src/applications/*_m.h
	$(Q)-rm -f src/common/*_m.cpp src/common/*_m.h
	$(Q)-rm -f src/messages/*_m.cpp src/messages/*_m.h
	$(Q)-rm -f src/utils/*_m.cpp src/utils/*_m.h
	$(Q)-rm -f tests/*_m.cpp tests/*_m.h
	$(Q)-rm -f tests/unit/*_m.cpp tests/unit/*_m.h
	$(Q)-rm -f tests/unit/utils/*_m.cpp tests/unit/utils/*_m.h
	$(Q)-rm -f tests/unit/utils/work/*_m.cpp tests/unit/utils/work/*_m.h
	$(Q)-rm -f tests/unit/utils/work/DNSToolsTEST/*_m.cpp tests/unit/utils/work/DNSToolsTEST/*_m.h
	$(Q)-rm -f tests/unit/utils/work/out/*_m.cpp tests/unit/utils/work/out/*_m.h
	$(Q)-rm -f tests/unit/utils/work/out/gcc-debug/*_m.cpp tests/unit/utils/work/out/gcc-debug/*_m.h
	$(Q)-rm -f tests/unit/utils/work/out/gcc-debug/DNSToolsTEST/*_m.cpp tests/unit/utils/work/out/gcc-debug/DNSToolsTEST/*_m.h

cleanall: clean
	$(Q)-rm -rf $(PROJECT_OUTPUT_DIR)

depend:
	$(qecho) Creating dependencies...
	$(Q)$(MAKEDEPEND) $(INCLUDE_PATH) -f Makefile -P\$$O/ -- $(MSG_CC_FILES)  ./*.cpp lib/*.cpp simulations/*.cpp src/*.cpp src/applications/*.cpp src/common/*.cpp src/messages/*.cpp src/utils/*.cpp tests/*.cpp tests/unit/*.cpp tests/unit/utils/*.cpp tests/unit/utils/work/*.cpp tests/unit/utils/work/DNSToolsTEST/*.cpp tests/unit/utils/work/out/*.cpp tests/unit/utils/work/out/gcc-debug/*.cpp tests/unit/utils/work/out/gcc-debug/DNSToolsTEST/*.cpp

# DO NOT DELETE THIS LINE -- make depend depends on it.
$O/src/utils/DNSTools.o: src/utils/DNSTools.cpp \
  src/utils/../messages/../common/DNS.h \
  src/utils/../common/DNS.h \
  src/utils/DNSTools.h \
  src/utils/../messages/DNSPacket_m.h
