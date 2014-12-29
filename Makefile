#
# OMNeT++/OMNEST Makefile for opp_dns_extension
#
# This file was generated with the command:
#  opp_makemake -f --deep --nolink -O out -d src -X. -I/usr/include/glib-2.0 -I/usr/lib/glib2.0 -L/LinuxFiles/Workspaces/opp_workspace/inet/out/$$\(CONFIGNAME\)/src -L./out/$$\(CONFIGNAME\)/src -linet -DINET_IMPORT -KINET_PROJ=/LinuxFiles/Workspaces/opp_workspace/inet
#

# Output directory
PROJECT_OUTPUT_DIR = out
PROJECTRELATIVE_PATH =
O = $(PROJECT_OUTPUT_DIR)/$(CONFIGNAME)/$(PROJECTRELATIVE_PATH)

# Other makefile variables (-K)
INET_PROJ=/LinuxFiles/Workspaces/opp_workspace/inet

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

all:  submakedirs Makefile
	@# Do nothing

submakedirs:  src_dir

.PHONY: all clean cleanall depend msgheaders  src
src: src_dir

src_dir:
	cd src && $(MAKE) all

msgheaders:
	$(Q)cd src && $(MAKE) msgheaders

clean:
	$(qecho) Cleaning...
	$(Q)-rm -rf $O
	$(Q)-rm -f opp_dns_extension opp_dns_extension.exe libopp_dns_extension.so libopp_dns_extension.a libopp_dns_extension.dll libopp_dns_extension.dylib

	-$(Q)cd src && $(MAKE) clean

cleanall: clean
	$(Q)-rm -rf $(PROJECT_OUTPUT_DIR)

depend:
	$(qecho) Creating dependencies...
	$(Q)-cd src && if [ -f Makefile ]; then $(MAKE) depend; fi

