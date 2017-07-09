#!/usr/bin/python                                                                            
                                                                                             
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI




class  SingleSwitchTopo(Topo):                                                                                                                                                                                               
    def build( self, count=1):                                                                                                                                                                                                                                                        
        s1 = self.build_sw(count)
      
           
    def build_sw(self, count):
        s1 = self.addSwitch( 's1')                                                                                           
        for i in range(count):  
           h = self.addHost( 'h%d' % (i+1), ip = '10.0.%d.2/24' % (i+1),  defaultRoute='via 10.0.%d.1' % (i+1))
           self.addLink( h, s1 )
        return s1


topos = { 'mytopo': ( lambda: SingleSwitchTopo(4)) }

