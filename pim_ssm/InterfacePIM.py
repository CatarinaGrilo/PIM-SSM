import socket
import random
import logging
import traceback
from threading import Timer

import netifaces
import Main
from RWLock.RWLock import RWLockWrite
from Interface import Interface
from Packet.ReceivedPacket import ReceivedPacket
from Packet.PacketPimHelloOptions import *
from Packet.PacketPimHello import PacketPimHello
from Packet.PacketPimHeader import PacketPimHeader
from Packet.Packet import Packet
from Neighbor import Neighbor
from tree.globals import HELLO_HOLD_TIME_TIMEOUT, REFRESH_INTERVAL


class InterfacePim(Interface):
    MCAST_GRP = '224.0.0.13'
    PROPAGATION_DELAY = 0.5
    OVERRIDE_INTERNAL = 2.5

    HELLO_PERIOD = 30
    TRIGGERED_HELLO_PERIOD = 5

    LOGGER = logging.getLogger('pim.Interface')

    def __init__(self, interface_name: str, vif_index:int):
        # generation id
        self.generation_id = random.getrandbits(32)
        self.DR_priority = 1

        # When PIM is enabled on an interface or when a router first starts, the Hello Timer (HT)
        # MUST be set to random value between 0 and Triggered_Hello_Delay
        self.hello_timer = None

        # todo: lan delay enabled
        self._lan_delay_enabled = False

        # todo: propagation delay
        self._propagation_delay = self.PROPAGATION_DELAY

        # todo: override interval
        self._override_interval = self.OVERRIDE_INTERNAL

        # pim neighbors
        self._had_neighbors = False
        self.neighbors = {}
        self.neighbors_lock = RWLockWrite()
        self.interface_logger = logging.LoggerAdapter(InterfacePim.LOGGER, {'vif': vif_index, 'interfacename': interface_name})

        # SOCKET
        if_addr_dict = netifaces.ifaddresses(interface_name)
        if not netifaces.AF_INET in if_addr_dict:
            raise Exception("Adding PIM interface failed because %s does not "
                            "have any ipv4 address" % interface_name)
        ip_interface = if_addr_dict[netifaces.AF_INET][0]['addr']
        self.ip_interface = ip_interface

        #Define DR election
        self.DR_ip = ip_interface
        self.DR_metric = self.DR_priority

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_PIM)

        # allow other sockets to bind this port too
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # explicitly join the multicast group on the interface specified
        #s.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(Interface.MCAST_GRP) + socket.inet_aton(ip_interface))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                     socket.inet_aton(Interface.MCAST_GRP) + socket.inet_aton(ip_interface))
        s.setsockopt(socket.SOL_SOCKET, 25, str(interface_name + '\0').encode('utf-8'))

        # set socket output interface
        s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip_interface))

        # set socket TTL to 1
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)

        # don't receive outgoing packets
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

        super().__init__(interface_name, s, s, vif_index)
        super().enable()

        self.already_sent_hello = False
        self.force_send_hello()

    def get_ip(self):
        """
        Get IP of this interface
        """
        return self.ip_interface

    @staticmethod
    def get_kernel():
        """
        Get Kernel object
        """
        return Main.kernel

    def _receive(self, raw_bytes):
        """
        Interface received a new control packet
        """
        if raw_bytes:
            packet = ReceivedPacket(raw_bytes, self)
            self.PKT_FUNCTIONS.get(packet.payload.get_pim_type(), InterfacePim.receive_unknown)(self, packet)

    def send(self, data: bytes, group_ip: str=MCAST_GRP):
        """
        Send a new packet destined to group_ip IP
        """
        super().send(data=data, group_ip=group_ip)

    #Random interval for initial Hello message on bootup or triggered Hello message to a rebooting neighbor
    def force_send_hello(self, immediately=False):
        """
        Force the transmission of a new Hello message
        """
        if self.hello_timer is not None:
            self.hello_timer.cancel()
        if immediately:
            hello_timer_time = 0
        else:
            hello_timer_time = random.uniform(0, self.TRIGGERED_HELLO_PERIOD)
        self.hello_timer = Timer(hello_timer_time, self.send_hello)
        self.hello_timer.start()

    def send_hello(self):
        """
        Send a new Hello message
        Include in it the HelloHoldTime and GenerationID
        """
        #self.interface_logger.debug('Send Hello message')
        self.hello_timer.cancel()

        pim_payload = PacketPimHello()
        pim_payload.add_option(PacketPimHelloHoldtime(holdtime=3.5 * self.HELLO_PERIOD))
        pim_payload.add_option(PacketPimHelloGenerationID(self.generation_id))
        pim_payload.add_option(PacketPimHelloDrPriority(self.DR_priority))

        # TODO implementar LANPRUNEDELAY e OVERRIDE_INTERVAL por interface e nas maquinas de estados ler valor de interface e nao do globals.py
        #pim_payload.add_option(PacketPimHelloLANPruneDelay(lan_prune_delay=self._propagation_delay, override_interval=self._override_interval))

        ph = PacketPimHeader(pim_payload)
        packet = Packet(payload=ph)
        self.send(packet.bytes())
        
        if self.already_sent_hello == False:
            self.already_sent_hello = True

        # reschedule hello_timer
        self.hello_timer = Timer(self.HELLO_PERIOD, self.send_hello)
        self.hello_timer.start()

    def remove(self):
        """
        Remove this interface
        Clear all state
        """
        self.hello_timer.cancel()
        self.hello_timer = None

        # send pim_hello timeout message
        pim_payload = PacketPimHello()
        pim_payload.add_option(PacketPimHelloHoldtime(holdtime=HELLO_HOLD_TIME_TIMEOUT))
        pim_payload.add_option(PacketPimHelloGenerationID(self.generation_id))
        pim_payload.add_option(PacketPimHelloDrPriority(self.DR_priority))
        ph = PacketPimHeader(pim_payload)
        packet = Packet(payload=ph)
        self.send(packet.bytes())

        self.get_kernel().interface_change_number_of_neighbors()
        super().remove()

    def check_number_of_neighbors(self):
        has_neighbors = len(self.neighbors) > 0
        if has_neighbors != self._had_neighbors:
            self._had_neighbors = has_neighbors
            self.get_kernel().interface_change_number_of_neighbors()

    def new_or_reset_neighbor_info(self, neighbor_ip):
        """
        React to new neighbor or restart of known neighbor
        """
        return self.get_kernel().new_or_reset_neighbor_info(self.vif_index, neighbor_ip)

    def new_or_reset_neighbor(self, neighbor_ip):
        """
        React to new neighbor or restart of known neighbor
        """
        self.get_kernel().new_or_reset_neighbor(self.vif_index, neighbor_ip)

    def DR_election(self):
        """
        React to new neighbor or restart of known neighbor
        """
        dr_ip = self.DR_ip
        if self.DR_ip != self.ip_interface:
            if (self.DR_priority > self.DR_metric) or (self.DR_priority==self.DR_metric and self.ip_interface>self.DR_ip):
                self.DR_ip = self.ip_interface
                self.DR_metric = self.DR_priority
        for n in self.neighbors:
            if self.dr_is_better(self.neighbors[n], self.DR_metric, self.DR_ip) == True:
                self.DR_ip = self.neighbors[n].ip
                self.DR_metric = self.neighbors[n].DR_priority
        if dr_ip != self.DR_ip:
            self.get_kernel().dr_changed(self.vif_index)
            pass

    def dr_is_better(self, a, metric, ip):
        return (a.DR_priority> metric) or (a.DR_priority==metric and a.ip>ip)
    
    def i_am_dr(self):
        return self.DR_ip == self.ip_interface

    def get_neighbors(self):
        """
        Get list of known neighbors
        """
        return list(self.neighbors.values())

    def get_neighbor(self, ip):
        """
        Get specific neighbor by its IP
        """
        return self.neighbors.get(ip)

    def remove_neighbor(self, ip):
        """
        Remove known neighbor
        """
        with self.neighbors_lock.genWlock():
            del self.neighbors[ip]
            self.interface_logger.debug("Remove neighbor: " + ip)
            self.check_number_of_neighbors()

    ###########################################
    # Recv packets
    ###########################################
    def receive_hello(self, packet):
        """
        Receive an Hello packet
        """
        ip = packet.ip_header.ip_src
        #print("ip = ", ip)
        options = packet.payload.payload.get_options()

        if (1 in options) and (20 in options) and (19 in options):
            hello_hold_time = options[1].holdtime
            generation_id = options[20].generation_id
            DR_priority = options[19].DR_priority
        else:
            raise Exception

        with self.neighbors_lock.genWlock():
            if ip not in self.neighbors:
                if hello_hold_time == 0:
                    return
                print("ADD NEIGHBOR")
                self.neighbors[ip] = Neighbor(self, ip, generation_id, DR_priority, hello_hold_time)
                self.check_number_of_neighbors()
                self.DR_election()
                if self.new_or_reset_neighbor_info(ip):
                    #print("IMMIDIATE HELLO")
                    self.force_send_hello(immediately=True)
                else:
                    self.force_send_hello()
                self.new_or_reset_neighbor(ip)
                return
            else:
                neighbor = self.neighbors[ip]

        neighbor.receive_hello(generation_id, DR_priority, hello_hold_time)

    def receive_assert(self, packet):
        """
        Receive an Assert packet
        """
        ip = packet.ip_header.ip_src
        if ip in self.neighbors:
            pkt_assert = packet.payload.payload  # PacketPimAssert
            source = pkt_assert.source_address
            group = pkt_assert.multicast_group_address
            source_group = (source, group)

            try:
                self.get_kernel().get_routing_entry(source_group).recv_assert_msg(self.vif_index, packet)
            except:
                traceback.print_exc()

    def receive_join_prune(self, packet):
        """
        Receive Join/Prune packet
        """
        ip = packet.ip_header.ip_src
        if ip in self.neighbors:
            pkt_join_prune = packet.payload.payload  # PacketPimJoinPrune

            join_prune_groups = pkt_join_prune.groups
            for group in join_prune_groups:
                multicast_group = group.multicast_group
                joined_src_addresses = group.joined_src_addresses
                pruned_src_addresses = group.pruned_src_addresses

                for source_address in joined_src_addresses:
                    source_group = (source_address, multicast_group)
                    try:
                        self.get_kernel().get_routing_entry(source_group).recv_join_msg(self.vif_index, packet)
                    except:
                        traceback.print_exc()
                        continue

                for source_address in pruned_src_addresses:
                    source_group = (source_address, multicast_group)
                    try:
                        self.get_kernel().get_routing_entry(source_group).recv_prune_msg(self.vif_index, packet)
                    except:
                        traceback.print_exc()
                        continue

    
    def receive_igmp(self, source_group, has_members):
        """
        Received an igmp update
        """

        self.interface_logger.debug('Received IGMP update: ' + str(source_group) +
                                    '; has members: ' + str(has_members) + "\n")
        
        try:
            #print("Going to routing entry\n\n")
            self.get_kernel().get_routing_entry(source_group).igmp_update(self.vif_index, has_members)
        except:
            traceback.print_exc()

            
    def receive_unknown(self, packet):
        """
        Receive an unknown packet
        """
        raise Exception("Unknown PIM type: " + str(packet.payload.get_pim_type()))

    PKT_FUNCTIONS = {
        0: receive_hello,
        3: receive_join_prune,
        5: receive_assert
    }