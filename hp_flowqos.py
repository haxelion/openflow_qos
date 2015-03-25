import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.ip import ipv4_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, ipv6, tcp, udp
from sipparser import SIPParser


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    AUTHORIZED_SERVER = '10.0.0.1'
    SIP_PORT = 5060
    LIST_MAX = 100
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.pending_qos = []

    def l3_resolve(self, did, ip):
        if ip in self.ip_to_mac:
            if self.ip_to_mac[ip] in self.mac_to_port[did]:
                return self.mac_to_port[did][self.ip_to_mac[ip]]
            else:
                self.logger.info("[L2] Unknown mac {}".format(self.ip_to_mac[ip]))
                return None
        else:
            self.logger.info("[L3] Unknown ip {}".format(ip))
            return None

    def add_qos_l4_flow(self, datapath, host1, host2, protocol, priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if host1[1] == 5060 or host2[1] == 5060:
            return
        port1 = self.l3_resolve(datapath.id, host1[0])
        port2 = self.l3_resolve(datapath.id, host2[0])
        if port1 == None or port2 == None:
            return
        self.logger.info('[L4] flow between {}:{} and {}:{} with priority {}'.format(host1[0], host1[1], host2[0], host2[1], priority))
        # priority path host1 -> host2
        actions = [parser.OFPActionVlanPcp(priority),
                   parser.OFPActionOutput(port2)]
        match = parser.OFPMatch(in_port = port1,
                                dl_type = 0x800,
                                nw_proto = protocol,
                                nw_src = struct.unpack('!I', ipv4_to_bin(host1[0]))[0],
                                nw_dst = struct.unpack('!I', ipv4_to_bin(host2[0]))[0],
                                tp_src = int(host1[1]),
                                tp_dst = int(host2[1]))
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=20,
                                hard_timeout=0,
                                priority=3000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)
        # priority path host2 -> host1
        actions = [parser.OFPActionVlanPcp(priority),
                   parser.OFPActionOutput(port1)]
        match = parser.OFPMatch(in_port = port2,
                                dl_type = 0x800,
                                nw_proto = protocol,
                                nw_src = struct.unpack('!I', ipv4_to_bin(host2[0]))[0],
                                nw_dst = struct.unpack('!I', ipv4_to_bin(host1[0]))[0],
                                tp_src = int(host2[1]),
                                tp_dst = int(host1[1]))
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=20,
                                hard_timeout=0,
                                priority=3000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)
 
    def add_l3_flow(self, datapath, host1, host2, proto):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        port1 = self.l3_resolve(datapath.id, host1)
        port2 = self.l3_resolve(datapath.id, host2)
        if port1 == None or port2 == None:
            return
        self.logger.info('[L3] flow between {} and {}'.format(host1, host2))
        # host1 -> host2
        actions = [parser.OFPActionOutput(port2)]
        match = parser.OFPMatch(dl_type = 0x800,
                                nw_src = struct.unpack('!I', ipv4_to_bin(host1))[0],
                                nw_dst = struct.unpack('!I', ipv4_to_bin(host2))[0],
                                nw_proto = proto)
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=20,
                                hard_timeout=0,
                                priority=1000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)
        # host2 -> host1
        actions = [parser.OFPActionOutput(port1)]
        match = parser.OFPMatch(dl_type = 0x800,
                                nw_src = struct.unpack('!I', ipv4_to_bin(host2))[0],
                                nw_dst = struct.unpack('!I', ipv4_to_bin(host1))[0],
                                nw_proto = proto)
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=20,
                                hard_timeout=0,
                                priority=1000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)


    def learn_host(self, datapath, pkt, in_port):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt != None:
            mac = eth_pkt.src
            if datapath.id not in self.mac_to_port:
                self.mac_to_port[datapath.id] = {}
            self.mac_to_port[datapath.id][mac] = in_port
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt != None:
                host1 = []
                host2 = []
                host1.append(ip_pkt.src)
                host2.append(ip_pkt.dst)
                self.ip_to_mac[host1[0]] = mac
                proto = ip_pkt.proto
                if proto == 6:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    host1.append(tcp_pkt.src_port)
                    host2.append(tcp_pkt.dst_port)
                    # add non prioritary flow
                    self.add_qos_l4_flow(datapath, host1, host2, proto, 1)
                elif proto == 0x11:
                    udp_pkt = pkt.get_protocol(udp.udp)
                    host1.append(udp_pkt.src_port)
                    host2.append(udp_pkt.dst_port)
                    # add non prioritary flow
                    self.add_qos_l4_flow(datapath, host1, host2, proto, 1)
                else:
                    self.add_l3_flow(datapath, host1[0], host2[0], proto)

    def sip_handler(self, datapath, msg):
        src_ip = ''
        dst_ip = ''
        proto = 0
        offset = 14 # ethernet header length
        is_sip = False
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt != None:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto = ip_pkt.proto
            offset += ip_pkt.header_length*4 # ipv4 header length in 4 bytes word
        if proto == 6:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt != None and (tcp_pkt.dst_port == self.SIP_PORT or tcp_pkt.src_port == self.SIP_PORT):
                offset += tcp_pkt.offset # tcp headers length
                is_sip = True
        elif proto == 0x11:
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt != None and (udp_pkt.dst_port == self.SIP_PORT or udp_pkt.src_port == self.SIP_PORT):
                offset += 8 # udp header length
                is_sip = True
        if is_sip:
            sip = SIPParser(msg.data[offset:])
            if sip.has_sdp:
                self.logger.info('[SIP] %s to %s for call %s: %s', src_ip, dst_ip, sip.call_id, sip.request) 
                self.logger.info('[SDP] %s:%s', sip.c_ip, sip.m_port)
                if sip.request.startswith('INVITE'):
                    self.pending_qos.append([sip.call_id, (sip.c_ip, sip.m_port)])
                    # avoid building a list too big by dropping old pending request
                    if len(self.pending_qos) > self.LIST_MAX:
                        self.pending_qos.pop()
                elif '200' in sip.request:
                    host2 = None
                    for p in self.pending_qos:
                        if p[0] == sip.call_id:
                            host2 = p[1]
                            self.pending_qos.remove(p)
                    if host2 != None:
                        self.add_qos_l4_flow(datapath, (sip.c_ip, sip.m_port), host2, 0x11, 7)
 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]#ofproto.OFP_NO_BUFFER)]
        # snooping SIP over UDP
        match = parser.OFPMatch(dl_type = 0x800,
                                nw_src = struct.unpack('!I', ipv4_to_bin(self.AUTHORIZED_SERVER))[0],
                                nw_proto = 0x11,
                                tp_src = self.SIP_PORT)
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=0,
                                hard_timeout=0,
                                priority=2000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)
        match = parser.OFPMatch(dl_type = 0x800,
                                nw_dst = struct.unpack('!I', ipv4_to_bin(self.AUTHORIZED_SERVER))[0],
                                nw_proto = 0x11,
                                tp_dst = self.SIP_PORT)
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=0,
                                hard_timeout=0,
                                priority=2000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)
        # snooping SIP over TCP
        match = parser.OFPMatch(dl_type = 0x800,
                                nw_src = struct.unpack('!I', ipv4_to_bin(self.AUTHORIZED_SERVER))[0],
                                nw_proto = 6,
                                tp_src = self.SIP_PORT)
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=0,
                                hard_timeout=0,
                                priority=2000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)
        match = parser.OFPMatch(dl_type = 0x800,
                                nw_dst = struct.unpack('!I', ipv4_to_bin(self.AUTHORIZED_SERVER))[0],
                                nw_proto = 6,
                                tp_dst = self.SIP_PORT)
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=0,
                                hard_timeout=0,
                                priority=2000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        dst = pkt.get_protocol(ethernet.ethernet).dst 
        dpid = datapath.id
        # L3 and L2 learning
        self.learn_host(datapath, pkt, msg.in_port)
        # SIP handling
        self.sip_handler(datapath, msg)

        # Manually output packet
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        action = parser.OFPActionOutput(out_port)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=[action], data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)
