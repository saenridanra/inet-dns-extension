# Omnet++ DNS Extension

This extensions provides classes and functions to simulate DNS and
MDNS traffic.

## Features

### DNS
- Name servers with recursive resolving capabilities
- Authoritative servers with DNS zone configuration using master files
- Caching servers without zones, only recursively resolving
- DNS Cache base that can be extended
  - Caches based on different policies possible
- DNS Client that can query a DNS server

See RFC 1035 https://tools.ietf.org/html/rfc1035 as a reference.

### Stateless DNS
- Stateless DNS simulation according to
https://netfuture.ch/2014/12/stateless-dns/.
- Echoserver impelementation currently supporting:
  - `.00.` - reflects the address in the query to the alias
  - `cca` - builds a cname chain, pointing to an address

  operations.

### MDNS
The avahi-daemon was used as a reference for designing MDNS resolvers in this
extension.

- MDNS resolver with the capabilities of
  - Publishing services via multicast
  - Revoking services via multicast
  - Perform queries via multicast
  - Known answer suppression
  - Duplicate question suppression
  - Duplicate answer suppression
  - Maintaining time schedules according to the RFC 6762

See RFC 6762 http://tools.ietf.org/html/rfc6762 for reference.

### MDNS Privacy

In parallel to the extension of the avahi-daemon to enhance privacy (https://netfuture.ch/2014/12/a-multicast-avoiding-privacy-extension-for-the-avahi-zeroconf-daemon/) we worked on a simulation that allows us to measure the effects of our
extension.

- Privacy extension according to the reference implementation done for the
avahi-daemon
- If the omnetpp code is edited, packets are visually distinguished. A tutorial
on how to do this can be found in the wiki.

## Installation and Usage

**Make sure you fulfill the requirements stated below.**

### Using the IDE

1. Get the source code for this extension.
2. Import the project into the Omnet++ IDE.
3. Import the INET framework into the IDE and build it.
4. Goto Project Properties > Omnet++ > Makemake
 - Select the src folder > Makemake > Options
 - Check shared library and
 - `Export this shared/static library for other projects`
 - If you want debug output include in the tabs
    - Custom > Makefrag `CFLAGS+= -DDEBUG_ENABLED CXXFLAGS+= -DDEBUG_ENABLED`
5. Include the compiled INET library object in the lib dir.
6. Enjoy

### Using the command line

1. Get the source code for this extension.
2. Change to the project directory.
3. Run `make makefiles` and provide the INET framework directory.
4. Run `make`.
5. To run examples you must run
        opp_run -l absolute_path_to_project \
        -l absolute_path_to_inet_library \
        -n absolute_path_to_project_src;absolute_path_to_inet_src" \
        absolute_path_to_simulation_ini_file

6. Enjoy

## Limitations

- All applications in this extension need to be wrapped within a Standard Host.
- Currently no rules like bailiwick have been implemented.
- Network Randomization currently not implemented, i.e.
  - Master Files have to be provided manually.
  - DNS Servers and network infrastucture has to be defined manually.
- MDNS Resolvers have to be configured manually.
  - This includes all relevant services published from the start.
  - This includes relevant information for the privacy extension.
- No statistics are currently recorded

## Future Work

- Proper network randomization for all applications
  - For DNS Servers and Clients
  - For MDNS Resolvers including the privacy extension
- Proper recording of relevant metrics
- Simulation network within a wireless area network
- More sophisticated DNS caches
- DNSSec extension
- Better integration with the existing Omnet++ structure


## Contributors

**Project maintainer**:

- Andreas Rain (andreas.rain(at){uni-konstanz.de , gmail.com}),
Github: @saenridanra
 - Project created as part of my master project
 to measure the effects of multicast
 traffic on wireless networks.

## Requirements

- working OMNeT++ (v4.4) installation. (Download from http://omnetpp.org)
- working INET-Framework installation (v2.3). (Download from http://inet.omnetpp.org)
- a compiler that supports c++11

Check whether the installations work using the examples provided in the INET
framework.

## Documentation

The projects code is fully documented using Doxygen and is placed
in the `doc` folder, next to the source code.

## License

This work is published under the MIT License http://opensource.org/licenses/MIT.
