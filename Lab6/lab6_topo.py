"""
Topooly for EL9333 Lab 6

"""

from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

import time

class MyTopo( Topo ):

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        # Hosts
        leftHost        = self.addHost( 'h1' )
        middleHost      = self.addHost( 'h2' )
        rightHost       = self.addHost( 'h3' )
        # Switches
        leftCoreSwitch   = self.addSwitch( 's1' )
        rightCoreSwitch  = self.addSwitch( 's2' )
        leftEdgeSwitch   = self.addSwitch( 's3' )
        middleEdgeSwitch = self.addSwitch( 's4' )
        righEdgetSwitch  = self.addSwitch( 's5' )

        # Add links
        self.addLink( leftHost         , leftEdgeSwitch   , 1, 1 )
        self.addLink( middleHost       , middleEdgeSwitch , 1, 1 )
        self.addLink( rightHost        , righEdgetSwitch  , 1, 1 )
        self.addLink( leftEdgeSwitch   , leftCoreSwitch   , 2, 1 )
        self.addLink( leftEdgeSwitch   , rightCoreSwitch  , 3, 1 )
        self.addLink( middleEdgeSwitch , leftCoreSwitch   , 2, 2 )
        self.addLink( middleEdgeSwitch , rightCoreSwitch  , 3, 2 )
        self.addLink( righEdgetSwitch  , leftCoreSwitch   , 2, 3 )
        self.addLink( righEdgetSwitch  , rightCoreSwitch  , 3, 3 )


topos = { 'mytopo': ( lambda: MyTopo() ) }

def runTraffic(self, line):
    "runTraffic generates UDP traffic among h1, h2 and h3"
    
    totalTime = 60 * 10 # 10 mins

    net = self.mn
    
    h1 = net.hosts[0]
    h2 = net.hosts[1]
    h3 = net.hosts[2]

    h1.cmd( 'arp -s ' + str( h2.IP() ) + ' ' + str( h2.MAC() ) )
    h1.cmd( 'arp -s ' + str( h3.IP() ) + ' ' + str( h3.MAC() ) )

    h2.cmd( 'arp -s ' + str( h1.IP() ) + ' ' + str( h1.MAC() ) )
    h2.cmd( 'arp -s ' + str( h3.IP() ) + ' ' + str( h3.MAC() ) )

    h3.cmd( 'arp -s ' + str( h1.IP() ) + ' ' + str( h1.MAC() ) )
    h3.cmd( 'arp -s ' + str( h2.IP() ) + ' ' + str( h2.MAC() ) )

    trafficList = [300, 200, 100]
    portList = [5555, 7777, 9999]

    timeCounter = 0

    while ( timeCounter < totalTime ):

        h1.cmd( 'iperf -c ' + str(h2.IP()) + ' -u -p ' + str( portList[0] ) +' -t 90 -b ' + str( trafficList[0] ) + 'K &' )
        h1.cmd( 'iperf -c ' + str(h3.IP()) + ' -u -p ' + str( portList[1] ) +' -t 90 -b ' + str( trafficList[1] ) + 'K &' )
        h2.cmd( 'iperf -c ' + str(h3.IP()) + ' -u -p ' + str( portList[2] ) +' -t 90 -b ' + str( trafficList[2] ) + 'K &' )

        for i in range( len( trafficList ) ):
            trafficList[i] -= 100
            if trafficList[i] <= 0:
                trafficList[i] = 300

        for i in range( len( portList ) ):
            portList[i] += 2

        time.sleep( 30 )
        timeCounter += 30
    
    #print h1.cmd('iperf -c ' + str(h2.IP()) + ' -u -p 54321 -t 10 -b 1M &')
    #print h1.cmd('iperf -c ' + str(h2.IP()) + ' -u -p 55331 -t 10 -b 1M &')


CLI.do_runTraffic = runTraffic