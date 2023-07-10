from abc import ABCMeta, abstractmethod
import Main
from threading import RLock
import traceback

from .downstream_join import DownstreamState
from .assert_ import AssertState, AssertStateABC

from Packet.PacketPimJoinPruneMulticastGroup import PacketPimJoinPruneMulticastGroup
from Packet.PacketPimHeader import PacketPimHeader
from Packet.Packet import Packet

from Packet.PacketPimJoinPrune import PacketPimJoinPrune
from Packet.PacketPimAssert import PacketPimAssert
from .metric import AssertMetric
from threading import Timer
from .local_membership import LocalMembership
from .globals import *
import logging

class TreeInterface(metaclass=ABCMeta):
    def __init__(self, kernel_entry, interface_id, logger: logging.LoggerAdapter):
        self._kernel_entry = kernel_entry
        self._interface_id = interface_id
        self.logger = logger
        self.assert_logger = logging.LoggerAdapter(logger.logger.getChild('Assert'), logger.extra)
        self.join_prune_logger = logging.LoggerAdapter(logger.logger.getChild('JoinPrune'), logger.extra)

        # Local Membership State
        try:
            interface_name = Main.kernel.vif_index_to_name_dic[interface_id]
            igmp_interface = Main.igmp_interfaces[interface_name]  # InterfaceIGMP
            group_state = igmp_interface.interface_state.get_group_state(kernel_entry.group_ip)
            #self._igmp_has_members = group_state.add_multicast_routing_entry(self)
            self._local_membership_state = LocalMembership.NoInfo
        except:
            self._local_membership_state = LocalMembership.NoInfo


        # Join State
        self._join_state = DownstreamState.NoInfo
        self._prune_pending_timer = None
        self._join_timer = None

        # Assert Winner State
        self._assert_state = AssertState.NoInfo
        self._assert_winner_metric = AssertMetric()
        self._my_assert_metric = self.my_assert_metric()
        self._assert_timer = None
        self.assert_logger.debug("Assert state transitions to NoInfo")

        # Received prune hold time
        self._received_join_holdtime = None

        self._igmp_lock = RLock()


    ############################################
    # Set ASSERT State
    ############################################
    def set_assert_state(self, new_state: AssertStateABC):
        with self.get_state_lock():
            if new_state != self._assert_state:
                self._assert_state = new_state
                self.assert_logger.debug('Assert state transitions to ' + str(new_state))

                self.change_tree()
                self.evaluate_ingroup()

    def set_assert_winner_metric(self, new_assert_metric: AssertMetric):
        with self.get_state_lock():
            try:
                old_neighbor = self.get_interface().get_neighbor(self._assert_winner_metric.get_ip())
                new_neighbor = self.get_interface().get_neighbor(new_assert_metric.get_ip())

                if old_neighbor is not None:
                    old_neighbor.unsubscribe_nlt_expiration(self)
                if new_neighbor is not None:
                    new_neighbor.subscribe_nlt_expiration(self)
            except:
                traceback.print_exc()
            finally:
                self._assert_winner_metric = new_assert_metric


    ############################################
    # ASSERT Timer
    ############################################
    def set_assert_timer(self, time):
        self.clear_assert_timer()
        self._assert_timer = Timer(time, self.assert_timeout)
        self._assert_timer.start()

    def clear_assert_timer(self):
        if self._assert_timer is not None:
            self._assert_timer.cancel()

    def assert_timeout(self):
        self._assert_state.assertTimerExpires(self)


    ###########################################
    # Recv packets
    ###########################################
    def recv_data_msg(self):
        pass

    def recv_assert_msg(self, received_metric: AssertMetric):
        print("Metric received:" + str(received_metric._metric_preference) + " " +  str(received_metric._route_metric))
        print("Metric AW:" + str(self._assert_winner_metric._metric_preference) + " " + str(self._assert_winner_metric._route_metric))
        print("Metric MINE:" + str(self.my_assert_metric()._metric_preference) + " " +  str(self.my_assert_metric()._route_metric))
        
        if self._assert_winner_metric.is_better_than(received_metric) and \
                self._assert_winner_metric.ip_address == received_metric.ip_address:
            # received inferior assert from Assert Winner
            print("INFERIOR AW")
            self._assert_state.receivedInferiorMetricFromWinner(self, received_metric)
        elif self.my_assert_metric().is_better_than(received_metric) and self.could_assert():
            # received inferior assert from non assert winner and could_assert
            print("INFERIOR NON-AW")
            self._assert_state.receivedInferiorMetricFromNonWinner_couldAssertIsTrue(self)
        elif received_metric.is_better_than(self._assert_winner_metric):
            # received preferred assert
            print("PREFERED")
            self._assert_state.receivedPreferedMetric(self, received_metric)
        elif received_metric.is_better_than(self.my_assert_metric()) and received_metric.get_ip()==self._assert_winner_metric.get_ip():
            # received preferred assert
            print("ACCEPTABLE")
            self._assert_state.receivedAcceptableMetric(self, received_metric)

    def recv_prune_msg(self, upstream_neighbor_address, holdtime):
        if upstream_neighbor_address == self.get_ip():
            #self._assert_state.receivedPruneOrJoinOrGraft(self)
            pass

    def recv_join_msg(self, upstream_neighbor_address, holdtime):
        if upstream_neighbor_address == self.get_ip():
            self._assert_state.receivedJoin(self)

    ######################################
    # Send messages
    ######################################
    def was_hello_sent(self):
        if self.get_interface().already_sent_hello == False:
            self.get_interface().force_send_hello(immediately=True)
            self.get_interface().already_sent_hello = True

    def send_prune(self, rpf=None, holdtime=None):
        self.was_hello_sent()
        
        if holdtime is None:
            holdtime = T_LIMIT

        if rpf is None:
            rpf = self.get_neighbor_RPF()

        print("send prune")
        try:
            (source, group) = self.get_tree_id()
            ph = PacketPimJoinPrune(rpf, holdtime)
            ph.add_multicast_group(PacketPimJoinPruneMulticastGroup(group, pruned_src_addresses=[source]))
            pckt = Packet(payload=PacketPimHeader(ph))

            self.get_interface().send(pckt.bytes())
            print('sent prune msg')
        except:
            traceback.print_exc()
            return

    def send_pruneecho(self):
        self.was_hello_sent()

        holdtime = T_LIMIT
        try:
            (source, group) = self.get_tree_id()
            ph = PacketPimJoinPrune(self.get_ip(), holdtime)
            ph.add_multicast_group(PacketPimJoinPruneMulticastGroup(group, pruned_src_addresses=[source]))
            pckt = Packet(payload=PacketPimHeader(ph))

            self.get_interface().send(pckt.bytes())
            print("send prune echo")
        except:
            traceback.print_exc()
            return

    def send_join(self, rpf=None, holdtime=None):
        self.was_hello_sent()

        if holdtime is None:
            holdtime = T_LIMIT

        if rpf is None:
            rpf = self.get_neighbor_RPF()
            
        print("send join")
        try:
            (source, group) = self.get_tree_id()
            ph = PacketPimJoinPrune(rpf, holdtime)
            ph.add_multicast_group(PacketPimJoinPruneMulticastGroup(group, joined_src_addresses=[source]))
            pckt = Packet(payload=PacketPimHeader(ph))

            self.get_interface().send(pckt.bytes())
        except:
            traceback.print_exc()
            return

    def send_assert(self):
        self.was_hello_sent()

        print("send assert")
        try:
            (source, group) = self.get_tree_id()
            assert_metric = self.my_assert_metric()
            ph = PacketPimAssert(multicast_group_address=group, source_address=source, metric_preference=assert_metric.metric_preference, metric=assert_metric.route_metric)
            pckt = Packet(payload=PacketPimHeader(ph))

            self.get_interface().send(pckt.bytes())
        except:
            traceback.print_exc()
            return

    def send_assert_cancel(self):
        self.was_hello_sent()

        print("send assert cancel")
        try:
            (source, group) = self.get_tree_id()
            ph = PacketPimAssert(multicast_group_address=group, source_address=source, metric_preference=float("Inf"), metric=float("Inf"))
            pckt = Packet(payload=PacketPimHeader(ph))

            self.get_interface().send(pckt.bytes())
        except:
            traceback.print_exc()
            return
        
    #############################################################

    @abstractmethod
    def is_forwarding(self):
        pass

    def assert_winner_nlt_expires(self):
        self._assert_state.winnerLivelinessTimerExpires_GenIDChanged(self)

    @abstractmethod
    def new_or_reset_neighbor_info(self, neighbor_ip):
        raise NotImplementedError()
    
    @abstractmethod
    def new_or_reset_neighbor(self, neighbor_ip):
        raise NotImplementedError()
    
    def dr_changed(self):
        #self.change_tree()
        self.evaluate_ingroup()
        if not self.could_assert():
            self._assert_state.couldAssertIsNowFalse(self)
        if not self.assert_tracking_desired():
            self._assert_state.assertTrackingDesiredIsNowFalse(self)

    @abstractmethod
    def delete(self, change_type_interface=False):
        if change_type_interface:
            if self.could_assert():
                self._assert_state.couldAssertIsNowFalse(self)

        (s, g) = self.get_tree_id()
        # unsubscribe igmp information
        try:
            interface_name = Main.kernel.vif_index_to_name_dic[self._interface_id]
            igmp_interface = Main.igmp_interfaces[interface_name]  # InterfaceIGMP
            print("HERE IN DELETE\n\n\n\n")
            group_state = igmp_interface.interface_state.get_group_state(g)
            group_state.remove_multicast_routing_entry(self)
        except:
            pass

        # Join State
        self._join_state = None

        # Assert State
        self._assert_state = None
        self.set_assert_winner_metric(AssertMetric.infinite_assert_metric()) # unsubscribe from current AssertWinner NeighborLivenessTimer
        self._assert_winner_metric = None
        self.clear_assert_timer()

        print('Tree Interface deleted')

    def is_olist_null(self):
        return self._kernel_entry.is_olist_null()

    def evaluate_ingroup(self):
        self._kernel_entry.evaluate_olist_change()


    #############################################################
    # Local Membership (IGMP)
    ############################################################
    def notify_igmp(self, has_members: bool):
        with self.get_state_lock():
            with self._igmp_lock:
                #print("In notigy_igmp\nhas_members: " + str(has_members) + "local: " + str(self._local_membership_state.has_members()))
                if has_members != self._local_membership_state.has_members():
                    self._local_membership_state = LocalMembership.Include if has_members else LocalMembership.NoInfo
                    self.change_tree()
                    self.evaluate_ingroup()
                    if not self.could_assert():
                        self._assert_state.couldAssertIsNowFalse(self)
                    if not self.assert_tracking_desired():
                        self._assert_state.assertTrackingDesiredIsNowFalse(self)


    def igmp_has_members(self):
        with self._igmp_lock:
            return self._local_membership_state.has_members()

    def get_interface(self):
        kernel = Main.kernel
        interface_name = kernel.vif_index_to_name_dic[self._interface_id]
        interface = Main.interfaces[interface_name]
        return interface


    def get_ip(self):
        ip = self.get_interface().get_ip()
        return ip

    def has_neighbors(self):
        try:
            return len(self.get_interface().neighbors) > 0
        except:
            return False

    def get_tree_id(self):
        return (self._kernel_entry.source_ip, self._kernel_entry.group_ip)

    def change_tree(self):
        self._kernel_entry.change()

    def get_state_lock(self):
        return self._kernel_entry.CHANGE_STATE_LOCK

    @abstractmethod
    def is_downstream(self):
        raise NotImplementedError()

    # obtain ip of RPF'(S)
    def get_neighbor_RPF(self):
        '''
        RPF'(S)
        '''
        if self.i_am_assert_loser():
            print("My rpf neighbor: ", self._assert_winner_metric.get_ip())
            return self._assert_winner_metric.get_ip()
        else:
            print("My rpf neighbor: ", self._kernel_entry.rpf_node)
            return self._kernel_entry.rpf_node

    def is_S_directly_conn(self):
        return self._kernel_entry.rpf_node == self._kernel_entry.source_ip

    def set_receceived_join_holdtime(self, holdtime):
        self._received_join_holdtime = holdtime

    def get_received_join_holdtime(self):
        return self._received_join_holdtime

    ###################################################
    # ASSERT
    ###################################################
    def lost_assert(self):
        if not self.is_downstream():
            return False
        else:
            return not self._assert_winner_metric.i_am_assert_winner(self) and \
                   self._assert_winner_metric.is_better_than(AssertMetric.spt_assert_metric(self))

    def i_am_assert_loser(self):
        return self._assert_state == AssertState.Loser

    def pim_include(self):
        return (((self.get_interface().i_am_dr() and self.lost_assert()==False) or self._assert_winner_metric.i_am_assert_winner(self)) \
            and self._local_membership_state == LocalMembership.Include)

    def could_assert(self):
        return self.is_downstream() and ((self._join_state == DownstreamState.Join or self._join_state == DownstreamState.PrunePending) or self.pim_include())
    
    def assert_tracking_desired(self):
        return (self._join_state == DownstreamState.Join or self._join_state == DownstreamState.PrunePending) or \
            (self._local_membership_state == LocalMembership.Include and \
             (self.get_interface().i_am_dr() or self._assert_winner_metric.i_am_assert_winner(self))) \
                or (not self.is_downstream() and not self.is_olist_null())

    def my_assert_metric(self):
        '''
        The assert metric of this interface for usage in assert state machine
        @rtype: AssertMetric
        '''
        if self.could_assert():
            return AssertMetric.spt_assert_metric(self)
        else:
            return AssertMetric.infinite_assert_metric()
        
    def my_assert_metric_changed(self):
        if self._my_assert_metric != self.my_assert_metric():
            self._my_assert_metric == self.my_assert_metric()
            if self._my_assert_metric.is_better_than(self._assert_winner_metric):
                self._assert_state.myAssertIsBetterThanAW(self)