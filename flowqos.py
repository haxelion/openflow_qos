from sipparser import SIPParser
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ipv6, tcp, udp


class FlowQoS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    AUTHORIZED_SERVER = '10.0.0.1'

    def __init__(self, *args, **kwargs):
        super(FlowQoS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # install SIP snooping entry for both UDP and TCP (for the weirdo out there)
        match = parser.OFPMatch(eth_type = 0x800, ipv4_src = self.AUTHORIZED_SERVER, ip_proto = 0x11, udp_src = 5060)
        self.add_flow(datapath, 3, match, actions)
        match = parser.OFPMatch(eth_type = 0x800, ipv4_dst = self.AUTHORIZED_SERVER, ip_proto = 0x11, udp_dst = 5060)
        self.add_flow(datapath, 3, match, actions)
        match = parser.OFPMatch(eth_type = 0x800, ipv4_src = self.AUTHORIZED_SERVER, ip_proto = 6, tcp_src = 5060)
        self.add_flow(datapath, 3, match, actions)
        match = parser.OFPMatch(eth_type = 0x800, ipv4_dst = self.AUTHORIZED_SERVER, ip_proto = 6, tcp_dst = 5060)
        self.add_flow(datapath, 3, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Check for SIP packet
        src_ip = ''
        dst_ip = ''
        proto = 0
        offset = 14 # ethernet header length
        is_sip = False
        ip_pkt = pkt.get_protocols(ipv4.ipv4)
        if len(ip_pkt) != 0:
            src_ip = ip_pkt[0].src
            dst_ip = ip_pkt[0].dst
            proto = ip_pkt[0].proto
            offset += ip_pkt[0].header_length*4 # ipv4 header length in 4 bytes word
        if proto == 6:
            tcp_pkt = pkt.get_protocols(tcp.tcp)
            if len(tcp_pkt) != 0 and (tcp_pkt[0].dst_port == 5060 or tcp_pkt[0].src_port == 5060):
                offset += tcp_pkt[0].offset
                is_sip = True
        elif proto == 0x11:
            udp_pkt = pkt.get_protocols(udp.udp)
            offset += 8 # udp header length
            if len(udp_pkt) != 0 and (udp_pkt[0].dst_port == 5060 or udp_pkt[0].src_port == 5060):
                is_sip = True
        if is_sip:
            sip = SIPParser(msg.data[offset:])
            self.logger.info('[SIP] %s to %s for call %s: %s', src_ip, dst_ip, sip.call_id, sip.request) 
            if sip.has_sdp:
                self.logger.info('\t[SDP] %s:%s', sip.c_ip, sip.m_port)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
