
from mininet.topo import Topo

class MyTopo( Topo ):
    BottomLayerSwitchList = []
    TopLayerSwitchList = []
    HostList = []

    def __init__( self ):
        NUMBER = 4
        self.NUMBER = NUMBER
        self.BottomLayerSwitch = NUMBER*2
        self.TopLayerSwitch = NUMBER
        self.Host = NUMBER*NUMBER*2
        Topo.__init__(self)

        #Add host and switches
        for i in range(1, self.TopLayerSwitch+1):
            NAME = "top_s"
            self.TopLayerSwitchList.append(self.addSwitch(NAME + str(i)))

        for i in range(1, self.BottomLayerSwitch+1):
            NAME = "down_s"
            self.BottomLayerSwitchList.append(self.addSwitch(NAME + str(i)))

        for i in range(1, self.Host+1):
            NAME = "host_"
            self.HostList.append(self.addHost(NAME + str(i)))    

        #Add Links

        for i in range(self.TopLayerSwitch):
            for j in range(self.BottomLayerSwitch):
                self.addLink(self.TopLayerSwitchList[i], self.BottomLayerSwitchList[j])

        for i in range(self.BottomLayerSwitch):
            for j in range(self.Host):
                self.addLink(self.BottomLayerSwitchList[i], self.HostList[j])

topos = { 'mytopo': ( lambda: MyTopo() ) }