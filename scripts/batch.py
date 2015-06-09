#!/usr/bin/python
import subprocess
import time
import sys, getopt
from multiprocessing import Process

'''
    file: batch.py
    author: Andreas Rain, Distributed Systems Group, University of Konstanz
    date: May 19th, 2015

    description: This script provides the means of running a batch of omnet++
    simulation runs in parallel using multiple processes.

    usage example:

    ./batch.py --PROJECT_PATH=/path/to/inet_dns_extensionn \
               --INET_PATH=/path/to/inet \
               --SIMULATION_DIR=src/networks/dynamic_mdns_network \
               --CONFIG=Batch10Resolvers --RUN_LOW=0 --RUN_HIGH=825 \
               --NUM_PROCESSES=4
'''

def run_command(cmd):
    subprocess.call(cmd, shell=True)

def performRun(low, high):
    global PROJECT_PATH
    global INET_PATH
    global SIMULATION_DIR
    global CONFIG
    global RUN_LOW
    global RUN_HIGH
    global NUM_PROCESSES

    while low < high and low < RUN_HIGH:
    	s = time.time()
        # create command with current from value
        print "Starting RUN: %s" % low
        cmd = 'cd {0}/{2} && opp_run -l {0}/src/inet_dns_extension -l {0}/lib/inet -n "{0}/src;{1}/src" {0}/{2}/omnetpp.ini -u Cmdenv -c {3} -r {4} > /dev/null'.format(PROJECT_PATH, INET_PATH, SIMULATION_DIR, CONFIG, low)
        run_command(cmd)
        e = time.time()
        w =  e - s
        print "Run took: " + str(w) + "s"
        low += 1

def main(argv):
    global PROJECT_PATH
    global INET_PATH
    global SIMULATION_DIR
    global CONFIG
    global RUN_LOW
    global RUN_HIGH
    global NUM_PROCESSES

    try:
      opts, args = getopt.getopt(argv, "", ["help", "PROJECT_PATH=","INET_PATH=","SIMULATION_DIR=","CONFIG=","INET_PATH=","RUN_LOW=","RUN_HIGH=","NUM_PROCESSES="])
    except getopt.GetoptError:
      print 'batch.py --PROJECT_PATH=<PROJECT_PATH> --INET_PATH=<INET_PATH> --SIMULATION_DIR=<SIMULATION_DIR> --CONFIG=<CONFIG> --RUN_LOW=<RUN_LOW> --RUN_HIGH=<RUN_HIGH> --NUM_PROCESSES=<NUM_PROCESSES>'
      sys.exit(2)
    for opt, arg in opts:
        if opt == '--help':
            print 'batch.py --PROJECT_PATH=<PROJECT_PATH> --INET_PATH=<INET_PATH> --SIMULATION_DIR=<SIMULATION_DIR> --CONFIG=<CONFIG> --RUN_LOW=<RUN_LOW> --RUN_HIGH=<RUN_HIGH> --NUM_PROCESSES=<NUM_PROCESSES>'
            sys.exit()
        elif opt in ("--PROJECT_PATH"):
            PROJECT_PATH = arg
        elif opt in ("--INET_PATH"):
            INET_PATH = arg
        elif opt in ("--SIMULATION_DIR"):
            SIMULATION_DIR = arg
        elif opt in ("--CONFIG"):
            CONFIG = arg
        elif opt in ("--RUN_LOW"):
            RUN_LOW = int(arg)
        elif opt in ("--RUN_HIGH"):
            RUN_HIGH = int(arg)
        elif opt in ("--NUM_PROCESSES"):
            NUM_PROCESSES = int(arg)

    startTime = time.time()

    # create Pool of N processes
    processes = []
    i = RUN_LOW
    stepSize = (RUN_HIGH - RUN_LOW) / NUM_PROCESSES

    while i < RUN_HIGH:
        print "Starting runs from {0} to {1}".format(i, i+stepSize)
        p = Process(target=performRun, args=(i, i+stepSize))
        processes.append(p)
        i+=stepSize

    for process in processes:
        process.start()

    for process in processes:
        process.join()

    endTime = time.time()
    workTime =  endTime - startTime

    #print results
    print "The batch took " + str(workTime) + " seconds to complete"

if __name__ == "__main__":
    main(sys.argv[1:])
