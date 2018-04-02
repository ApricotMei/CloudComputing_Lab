from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )
        s4 = self.addSwitch( 's4' )

        # Add links
        self.addLink( h1, s1 )
        self.addLink( s1, s2 )
        self.addLink( s1, s4 )
        self.addLink( s2, h2 )
        self.addLink( s2, s3 )
        self.addLink( s4, h4 )
        self.addLink( s4, s3 )
        self.addLink( s3, h3 )

          

topos = { 'mytopo': ( lambda: MyTopo() ) }
