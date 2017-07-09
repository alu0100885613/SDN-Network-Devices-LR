# -*- coding: utf-8 -*-

import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet

from netaddr import *


from ryu import cfg


  
LOG = logging.getLogger('Router')
LOG.setLevel(logging.INFO)
logging.basicConfig()  

# Configuración de direcciones IP asignadas a los puertos.
# Congifuración de direcciones MAC de cada puerto.
class Ports:

    def __init__(self, filename):
      self.ports = dict()
      self.ips = dict()
      import csv
      try:
         with open(filename, 'rb') as csvfile:
          reader = csv.reader(csvfile, delimiter=' ', quotechar='|')
          for row in reader:
             LOG.info(row)
             self.add_port(int(row[0]), row[1], row[2], row[3])
         
      except:
        LOG.debug("File not found")
    
    def add_port(self, port, ip, mask, mac):
      self.ports[port] = (ip, mask, mac)
      self.ips[ip] = (port,mask,mac)
    
    def get_port(self, port):
      return self.ports[port]
    
    def get_ip(self, ip):
      if ip in self.ips.keys():
	return self.ips[ip]
      else:
	return None
        
# Caché ARP        
class ARPCache:
   def __init__(self):
      self.ip_port = dict()
      
   def set_mac(self, ip, mac, port):
      self.ip_port[(ip,port)] = mac
   
   def get_mac(self, ip, port):
      if (ip,port) in self.ip_port.keys():
	return self.ip_port[(ip,port)]
      else:
	return None

# Tabla de firewall
class FirewallingTable:
  def __init__(self,filename):
    self.table = []

    import csv
    try:
       with open(filename, 'rb') as csvfile:
         reader = csv.reader(csvfile, delimiter=' ', quotechar='|')
         for row in reader:
            LOG.info(row)
            self.add_firewall(int(row[0]), int(row[1]), row[2], row[3], row[4], row[5])

    except:
       LOG.debug("File not found")

    LOG.info(self.table)

  def add_firewall(self, port_src, port_dst, ip_src, ip_dst, protocol, action):

    self.table.append((port_src, port_dst, ip_src, ip_dst, protocol, action))

    
# Tabla de enrutamiento    
class RoutingTable:
  def __init__(self, ports, filename):
    self.table = []
    for p in ports.ports.keys():
      (ip, mask, mac) = ports.ports[p]
      ip = IPNetwork("%s/%s" % (ip, mask))
      self.add_route(str(ip.network), ip.prefixlen, p, None)
    
    import csv
    try:
       with open(filename, 'rb') as csvfile:
         reader = csv.reader(csvfile, delimiter=' ', quotechar='|')
         for row in reader:
            LOG.info(row)
            self.add_route(row[0], int(row[1]), int(row[2]), row[3])
         
    except:
       LOG.debug("File not found")  
      
    LOG.info(self.table)
  
  def add_route(self, network, mask, port, next_hop):
    
    self.table.append((network, mask, port, next_hop))
  
  def search(self, ip):
      current_route = None
      current_mask = 0

      for row in self.table:
        str_mask = str(row[1])
        aux = IPNetwork("%s/%s" % (ip, str_mask))
        result = aux.ip & aux.netmask

        if result == IPAddress(row[0]) and current_mask < row[1]:
            current_route = (row[0],row[1],row[2],row[3])
            current_mask = row[1]

      return current_route

# Gestión de paquetes pendientes de
# envío debido a la espera de una
# respuesta ARP.
class PendingPackets:
  def __init__(self):
    self.pending = dict()
  
  def addPendingPacket(self, ip, msg, dst_ip, priority):
    if not ip in self.pending.keys():
      self.pending[ip] = list()
     
    self.pending[ip].append((msg, dst_ip,priority))
  
  def getPendingPackets(self, ip):
    if ip in self.pending.keys():
      lst = self.pending[ip]
      del self.pending[ip]
      return lst
    else:
      return []


     
     
class Router(app_manager.RyuApp):

    def __init__(self,*args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        name = "r1"
        LOG.info("Configuring %s" % (name))
        self.name = name
        self.ports = Ports('%s_ports.csv' % (name))
        self.arpcache = ARPCache()
        self.routing = RoutingTable(self.ports, '%s_routing.conf' % (name))
        self.pending = PendingPackets()
        self.firewall = FirewallingTable("%s_firewalling.csv" % (name))
        
    
    # Configuración inicial del switch.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        datapath.id = msg.datapath_id

        ofproto_parser = datapath.ofproto_parser

        set_config = ofproto_parser.OFPSetConfig(
            datapath,
            datapath.ofproto.OFPC_FRAG_NORMAL,
            datapath.ofproto.OFPCML_MAX,
        )
	
        datapath.send_msg(set_config)
	
        match = datapath.ofproto_parser.OFPMatch()

        actions = [datapath.ofproto_parser.OFPActionOutput(
                datapath.ofproto.OFPP_CONTROLLER,
                datapath.ofproto.OFPCML_NO_BUFFER)]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath,
                priority=0,
                buffer_id=0xffffffff,
                match=match,
                instructions=inst)
        datapath.send_msg(mod)
        
        self.set_sw_config_for_ttl(datapath)
        self.firewarding(datapath)

        
        LOG.debug("Initial configuration done")
    
    def set_sw_config_for_ttl(self, dp):
       packet_in_mask = (1 << dp.ofproto.OFPR_ACTION |  1 << dp.ofproto.OFPR_INVALID_TTL)
       port_status_mask = (1 << dp.ofproto.OFPPR_ADD | 1 << dp.ofproto.OFPPR_DELETE |1 << dp.ofproto.OFPPR_MODIFY)
       flow_removed_mask = (1 << dp.ofproto.OFPRR_IDLE_TIMEOUT |
                            1 << dp.ofproto.OFPRR_HARD_TIMEOUT | 1 << dp.ofproto.OFPRR_DELETE)
       m = dp.ofproto_parser.OFPSetAsync(dp, [packet_in_mask, 0], [port_status_mask, 0],[flow_removed_mask, 0])
       dp.send_msg(m)
       
    # Packetin Handler.   
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
    
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        inPort = msg.match['in_port']
        
        if msg.reason == ofproto.OFPR_INVALID_TTL:
	   self.ttl_exceeded_response(msg)
	   return

        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet.ethernet)
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            self.receive_arp(datapath, packet, etherFrame, inPort)
        elif etherFrame.ethertype == ether.ETH_TYPE_IP:
            self.receive_ip(msg, inPort)
        else:
            LOG.debug("receive Unknown packet %s => %s (port%d)"
                       %(etherFrame.src, etherFrame.dst, inPort))
            LOG.debug("Drop packet")
            return 1
        return 0
      
    # Se ejecuta cuando se recibe un paquete
    # debido a un TLL excedido.
    def ttl_exceeded_response(self,msg):
        LOG.info('TTL exceeded')
        None
     
    # Gestión de paquetes IP 
    def receive_ip(self, msg, port):
        datapath = msg.datapath
        packet = Packet(msg.data)
        
        ip_packet = packet.get_protocol(ipv4.ipv4)
        LOG.debug("receive IP packet at port %d" % port)
	eth_packet = packet.get_protocol(ethernet.ethernet)
	
	self.arpcache.set_mac(ip_packet.src,  eth_packet.src, port)
	(port_ip, port_mask, port_mac) = self.ports.get_port(port) 
	if ip_packet.proto == inet.IPPROTO_ICMP:
             ret = self.receive_icmp(datapath, packet, port)
             if ret == 1:
	       return
        
	self.forwarding(msg)
        LOG.debug("Packet forwarding: " + str(packet))
        return
      
    # Gestión de paquetes ICMP.  
    def  receive_icmp(self, datapath, packet, port):
   
        ip_packet = packet.get_protocol(ipv4.ipv4)
        icmp_packet = packet.get_protocol(icmp.icmp)
        
        if icmp_packet.type == 8: # Echo request
	   dst_mac = self.arpcache.get_mac(ip_packet.src, port)
	   
	   ip_data =  self.ports.get_ip(ip_packet.dst)
           if (ip_data == None):
	     LOG.debug("ICMP not for router")
	     return 0
	   
	   (ip_addr,mask,mac_addr) = self.ports.get_port(port) # Routing
           
           e =  ethernet.ethernet(dst_mac, mac_addr, ether.ETH_TYPE_IP)
           ip = ipv4.ipv4(src= ip_packet.dst, dst=ip_packet.src, proto= inet.IPPROTO_ICMP,ttl=64)
	   echo_new = icmp.echo(icmp_packet.data.id, icmp_packet.data.seq, icmp_packet.data.data)
	   icmp_new = icmp.icmp(type_=0, code=0, data=echo_new)
           p = Packet()
           p.add_protocol(e)
           p.add_protocol(ip)
           p.add_protocol(icmp_new)
           
           self.send_packet(datapath,port, p)
           LOG.debug("ICMP for router")
           return 1
        return 0

    def firewarding(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = []

        for row in self.firewall.table:
            if(row[4] == "tcp"):
              match = parser.OFPMatch(tcp_src=row[0], tcp_dst=row[1], ipv4_src=IPAddress(row[2]), ipv4_dst = IPAddress(row[3]), ip_proto = 6 , eth_type = ether.ETH_TYPE_IP)
            else:
              match = parser.OFPMatch(udp_src=row[0], udp_dst=row[1], ipv4_src=IPAddress(row[2]), ipv4_dst = IPAddress(row[3]), ip_proto = 17 , eth_type = ether.ETH_TYPE_IP)

            if(row[5] == "Drop"):
              self.add_flow_drop(datapath, 1, match, actions)
            else:
              self.add_flow_goto(datapath, 1, match, actions)

        None

    # Gestion del reenvío de paquetes.
    def forwarding(self, msg):

        packet = Packet(msg.data)
        ip_packet = packet.get_protocol(ipv4.ipv4)

        entry = self.routing.search(ip_packet.dst)

        if (entry[3] == None):
            next_hop = ip_packet.dst
            dir_ip = ip_packet.dst
        else:
            next_hop = entry[3]
            str_mask = str(entry[1])
            dir_ip = IPNetwork("%s/%s" % (entry[0], str_mask))

        next_mac = self.arpcache.get_mac(next_hop,entry[2])

        if(next_mac != None):
            self.add_forwarding_flow(msg, entry[2], dir_ip, next_mac, 32)
        else:
            self.arp_request(msg.datapath, next_hop, entry[2])
            self.pending.addPendingPacket(next_hop, msg, dir_ip, entry[1])

        None
        
   # Añade una entrada a la tabla de flujo para reenvío.
    def add_forwarding_flow(self, msg, port, dst_ip, dst_mac, priority):

        datapath = msg.datapath

        packet = Packet(msg.data)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        (ip,mask,eth_src) = self.ports.get_port(port)

        match = parser.OFPMatch(ipv4_dst = dst_ip, eth_type = ether.ETH_TYPE_IP)

        actions = [parser.OFPActionSetField(eth_dst=dst_mac),
        parser.OFPActionSetField(eth_src=eth_src),
        parser.OFPActionOutput(port=port)]

        self.add_flow(datapath,priority, match, actions, buffer_id=msg.buffer_id)
        
        None

    
    # Envía una petición ARP a través de un puerto.
    def arp_request(self, datapath, ip, port):
        p = Packet()
        (port_ip, port_mask, port_mac) = self.ports.get_port(port)
        p.add_protocol(ethernet.ethernet(src=port_mac, dst='ff:ff:ff:ff:ff:ff', ethertype=ether.ETH_TYPE_ARP))
        p.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=port_mac,src_ip=port_ip, dst_ip=ip))
        
        self.send_packet(datapath,port,p)
      
    # Gestiona la recepción de paquetes ARP.  
    def receive_arp(self, datapath, packet, frame, port):
        arp_packet = packet.get_protocol(arp.arp)
        ip_addr = arp_packet.src_ip
        mac_addr = arp_packet.src_mac
        

        if arp_packet.opcode == 1:   # ARP request
            self.reply_arp(datapath, frame, packet, arp_packet.dst_ip, port)
        elif arp_packet.opcode == 2: # ARP reply
            self.arpcache.set_mac(ip_addr,  mac_addr, port)
            
            lst = self.pending.getPendingPackets(ip_addr)
            for (msg, dst_ip, prio) in lst:
                self.add_forwarding_flow(msg, port, dst_ip, mac_addr,prio)
            
        return 0
      
      
    # Genera una respuesta ARP en caso de que la consulta
    # esté dirigida a la dirección IP del puerto.
    def reply_arp(self, datapath, frame, packet, ip, port):
   
        (ip_addr, mask, mac_addr)=self.ports.get_port(int(port))
        LOG.debug("ARP reply: %s %s, ip: %s, port=%d" % (ip_addr, mac_addr, ip, port))
        LOG.debug("Router %s: %s" % (self.name, self.ports.ports))
        if (ip == ip_addr):  # Only generates a reply if the request is for router
	  arp_packet = packet.get_protocol(arp.arp)
          target_ip =  arp_packet.src_ip
          target_mac =  arp_packet.src_mac
	  e = ethernet.ethernet(target_mac, mac_addr, ether.ETH_TYPE_ARP)
          a = arp.arp(1, 0x0800, 6, 4, 2, mac_addr, ip_addr, target_mac, target_ip)
          p = Packet()
          p.add_protocol(e)
          p.add_protocol(a)


          self.send_packet(datapath,port,p)
          
    
    # Envía un paquete construido en el controlador a través de un puerto
    # del switch.
    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        LOG.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        
    #  Inserta una entrada a la tabla de flujo.
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
           mod = parser.OFPFlowMod(datapath=datapath,table_id=1,buffer_id=buffer_id,
                 priority=priority, match=match,
                 instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
        else:
           mod = parser.OFPFlowMod(datapath=datapath,table_id=1,priority=priority,
                 match=match, instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
   
        datapath.send_msg(mod)

    def add_flow_drop(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        if buffer_id:
           mod = parser.OFPFlowMod(datapath=datapath,buffer_id=buffer_id,
                 priority=priority, match=match,
                 instructions=inst)
        else:
           mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                 match=match, instructions=inst)

        datapath.send_msg(mod)


    def add_flow_goto(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionGotoTable(1)]

        if buffer_id:
           mod = parser.OFPFlowMod(datapath=datapath,buffer_id=buffer_id,
                 priority=priority, match=match,
                 instructions=inst)
        else:
           mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                 match=match, instructions=inst)

        datapath.send_msg(mod)


        
