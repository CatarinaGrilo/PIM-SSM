import socket
import struct
import netifaces
from ipaddress import IPv4Address
from ctypes import create_string_buffer, addressof

from Packet.ReceivedPacket import ReceivedPacket
from Interface import Interface
from igmpv3.igmp_globals import VERSION_3_QUERY, VERSION_3_REPORT
if not hasattr(socket, 'SO_BINDTODEVICE'):
    socket.SO_BINDTODEVICE = 25

ETH_P_IP = 0x0800		# Internet Protocol packet
#     The "Type" field in Ethernet II frames tells the OS what 
#     kind of data the frame carries – 0x0800 means that the 
#     frame has an IPv4 packet

SO_ATTACH_FILTER = 26


class InterfaceIGMP(Interface):
    FILTER_IGMP = [
        struct.pack('HBBI', 0x28, 0, 0, 0x0000000c),
        struct.pack('HBBI', 0x15, 0, 3, 0x00000800),
        struct.pack('HBBI', 0x30, 0, 0, 0x00000017),
        struct.pack('HBBI', 0x15, 0, 1, 0x00000002),
        struct.pack('HBBI', 0x6, 0, 0, 0x00040000),
        struct.pack('HBBI', 0x6, 0, 0, 0x00000000),
    ]


    def __init__(self, interface_name: str, vif_index: int = 0):
        if_addr_dict = netifaces.ifaddresses(interface_name)
        if not netifaces.AF_INET in if_addr_dict:
            raise Exception("Adding IGMP interface failed because %s does not "
                            "have any ipv4 address" % interface_name)
        self.ip_interface = if_addr_dict[netifaces.AF_INET][0]['addr']

        # SEND SOCKET
        snd_s = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)

        # bind to interface
        snd_s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                         str(interface_name + "\0").encode('utf-8'))

        # RECEIVE SOCKET
        rcv_s = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))

        # receive only IGMP packets by setting a BPF filter
        bpf_filter = b''.join(InterfaceIGMP.FILTER_IGMP)
        b = create_string_buffer(bpf_filter)
        mem_addr_of_filters = addressof(b)
        fprog = struct.pack(
            'HL', len(InterfaceIGMP.FILTER_IGMP), mem_addr_of_filters)
        rcv_s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)

        # bind to interface
        rcv_s.bind((interface_name, ETH_P_IP))
        super().__init__(interface_name=interface_name,
                         recv_socket=rcv_s, send_socket=snd_s, vif_index=vif_index)
        super().enable()
        
        from igmpv3.RouterState import RouterState
        self.interface_state = RouterState(self)
        
    @staticmethod
    def _get_address_family():
        return socket.AF_INET

    def get_ip(self):
        """
        Get IP of this interface
        :return:
        """
        return self.ip_interface

    def send(self, data: bytes, address: str):
        """
        Send a new control packet destined to address
        """
        super().send(data, address)

    def _receive(self, raw_bytes):
        """
        Interface received a new control packet
        """
        if raw_bytes:
            raw_bytes = raw_bytes[14:]
            packet = ReceivedPacket(raw_bytes, self)
            ip_src = packet.ip_header.ip_src
            if not (ip_src == "0.0.0.0" or IPv4Address(ip_src).is_multicast):
                self.PKT_FUNCTIONS.get(packet.payload.getIgmpType(), InterfaceIGMP.receive_unknown_type)(self, packet)

    ###########################################
    # Recv packets
    ###########################################

    def receive_version_3_membership_report(self, packet):
        """
        Interface received an IGMP Membership Report packet
        """
        ip_dst = packet.ip_header.ip_dst
        if ip_dst == "224.0.0.22":
            self.interface_state.receive_v3_membership_report(packet)

    def receive_version_3_membership_query(self, packet):
        """
        Interface received an IGMP Query packet
        """
        ip_dst = packet.ip_header.ip_dst
        igmp_group = packet.payload.getMCGroupAdress()
        if (IPv4Address(igmp_group).is_multicast and ip_dst == igmp_group) or (ip_dst == "224.0.0.1"):
            self.interface_state.receive_query(packet)

    @staticmethod
    def receive_unknown_type(packet):
        """
        Interface received an IGMP Unknown packet
        """
        ip_dst = packet.ip_header.ip_dst
        igmp_hdr = packet.payload

        igmp_type = igmp_hdr.type

        raise Exception(
            "Exception igmp packet: type={}; ip_dst={}".format(igmp_type, ip_dst))

    PKT_FUNCTIONS = {
        VERSION_3_REPORT: receive_version_3_membership_report,
        VERSION_3_QUERY: receive_version_3_membership_query,
    }

    ##################
    def remove(self):
        """
        Remove this interface
        Clear all state
        """
        super().remove()
        self.interface_state.remove()



