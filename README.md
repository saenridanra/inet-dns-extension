# DNS and mDNS models for INET

This extensions provides classes and functions to simulate DNS and
MDNS traffic.

[![Build Status](http://saenatwork.org/jenkins/job/inet-dns-extension/badge/icon)](http://saenridanra.de/jenkins/job/inet-dns-extension/)

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
- If the OMNeT++ code is edited, packets are visually distinguished. A tutorial
on how to do this can be found in the wiki.

## Installation and Usage

**Make sure you fulfill the requirements stated below.**

### Using the IDE

1. Get the source code for this extension.
2. Import the project as a C++ Makefile Project into the OMNeT++ IDE.
3. Import the INET (version >3.0) framework into the IDE and build it.
4. Right-click inet-dns-extension > Add OMNeT++ Support
5. Goto Project Properties > OMNeT++ > Makemake
 - Select the root folder
    - Under `Build` select `Makemake`
    - Under `Source` select `Excluded`
    - Goto `Options` under `Build`
       - Under `Target` select `No executable or library`
       - Under `Scope`, `Deep compile` and `Recursive make` must be selected

 - Select the src folder
    - Under `Build` select `Makemake`
    - Under `Source` select `Source Location`
    - Goto `Options` under `Build`
       - Under `Target` select `Shared library` and `Export this shared/static library for other projects`
       - Under `Scope`, `Deep compile` and `Recursive make` must be selected
       - Under `Compile`, make sure bot boxes for include paths are selected
6. Make sure the inet project is set as a reference under `Project Properties` > `Project References`
7. The project should now be able to build.
 - If you get an error about a message, run `make msgheaders` once and build again.
8. Enjoy

### Using the command line

1. Get the source code for this extension.
2. Change to the project directory.
3. Run `make makefiles` and provide the INET framework directory.
4. Run `make`.
5. To run examples you must run
        ```opp_run -l absolute_path_to_project \
        -l absolute_path_to_inet_library \
        -n absolute_path_to_project_src;absolute_path_to_inet_src" \
        absolute_path_to_simulation_ini_file```

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
- Better integration with the existing OMNeT++ structure


## Contributors

**Project maintainer**:

- Andreas Rain (andreas.rain(at){uni-konstanz.de , gmail.com}),
Github: @saenridanra
 - Project created as part of my master project
 to measure the effects of multicast
 traffic on wireless networks.

## Requirements

- working OMNeT++ installation - version 4.6 or higher. (Download from http://omnetpp.org)
- working INET-Framework installation - version 3 or higher. (Download from http://inet.omnetpp.org)
- a compiler that supports C++11

Check whether the installations work using the examples provided in the INET
framework.

## Documentation

The projects code is fully documented using Doxygen and is placed
in the `doc` folder, next to the source code.

## License

This work is published under the MIT License http://opensource.org/licenses/MIT.
