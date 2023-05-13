from .tree_interface import TreeInterface
from .upstream_join import UpstreamState
from threading import Timer
from CustomTimer.RemainingTimer import RemainingTimer
from .globals import *
import random
import traceback
from . import DataPacketsSocket
import threading
import logging
import Main


class TreeInterfaceUpstream(TreeInterface):
    LOGGER = logging.getLogger('pim.KernelEntry.UpstreamInterface')

    def __init__(self, kernel_entry, interface_id):
        extra_dict_logger = kernel_entry.kernel_entry_logger.extra.copy()
        extra_dict_logger['vif'] = interface_id
        extra_dict_logger['interfacename'] = Main.kernel.vif_index_to_name_dic[interface_id]
        logger = logging.LoggerAdapter(TreeInterfaceUpstream.LOGGER, extra_dict_logger)
        TreeInterface.__init__(self, kernel_entry, interface_id, logger)

        # Join State:
        self._join_state = UpstreamState.NotJoined
        self._join_timer = None
        self._last_rpf = self.get_neighbor_RPF()
        self.join_prune_logger.debug('Upstream state transitions to ' + str(self._join_state))

        # TODO TESTE SOCKET RECV DATA PCKTS
        self.socket_is_enabled = True
        (s,g) = self.get_tree_id()
        interface_name = self.get_interface().interface_name
        self.socket_pkt = DataPacketsSocket.get_s_g_bpf_filter_code(s, g, interface_name)

        # run receive method in background
        receive_thread = threading.Thread(target=self.socket_recv)
        receive_thread.daemon = True
        receive_thread.start()

        self.logger.debug('Created UpstreamInterface')


    def socket_recv(self):
        while self.socket_is_enabled:
            try:
                self.socket_pkt.recvfrom(0)
                print("PACOTE DADOS RECEBIDO")
                self.recv_data_msg()
            except:
                traceback.print_exc()
                continue

    ##########################################
    # Set state
    ##########################################
    def set_state(self, new_state):
        with self.get_state_lock():
            if new_state != self._join_state:
                self._join_state = new_state
                self.join_prune_logger.debug('Upstream state transitions to ' + str(new_state))

                self.change_tree()
                self.evaluate_ingroup()

    ##########################################
    # Check timers
    ##########################################
    def is_join_timer_running(self):
        return self._join_timer is not None and self._join_timer.is_alive()

    def remaining_join_timer(self):
        return 0 if not self._join_timer else self._join_timer.time_remaining()

    ##########################################
    # Set timers
    ##########################################

    def set_join_timer(self, time):
        self.clear_join_timer()
        self._join_timer = RemainingTimer(time, self.join_timeout)
        self._join_timer.start()

    def clear_join_timer(self):
        if self._join_timer is not None:
            self._join_timer.cancel()

    ###########################################
    # Timer timeout
    ###########################################
    def join_timeout(self):
        self._join_state.JTexpires(self)

    ###########################################
    # Recv packets
    ###########################################
    def recv_data_msg(self): #Maybe see if it is joined 
        return

    def recv_join_msg(self, upstream_neighbor_address, holdtime):
        super().recv_join_msg(upstream_neighbor_address, holdtime)
        self.set_receceived_join_holdtime(holdtime)
        if upstream_neighbor_address == self.get_neighbor_RPF():
            self._join_state.seeJoinToRPFnbr(self)

    def recv_prune_msg(self, upstream_neighbor_address, holdtime):
        super().recv_prune_msg(upstream_neighbor_address, holdtime)
        self.set_receceived_join_holdtime(holdtime)
        if upstream_neighbor_address == self.get_neighbor_RPF():
            self._join_state.seePruneToRPFnbr(self)

    ###########################################
    # Change olist
    ###########################################
    def olist_is_null(self):
        print("In olist_is_null\n")
        self._join_state.JoinDesired(self, False)

    def olist_is_not_null(self):
        print("In olist_is_not_null\n")
        self._join_state.JoinDesired(self, True)


    ###########################################
    # Changes to RPF'(s)
    ###########################################

    # caused by assert transition:
    def set_assert_state(self, new_state):
        print("Set_Assert_state\n\n")
        super().set_assert_state(new_state)
        current_rpf = self.get_neighbor_RPF()
        if self._last_rpf != current_rpf:
            print("rpf neighbor changed\n\n")
            self._last_rpf = current_rpf
            self._join_state.RPFnbrChangesOnAssert(self)

    # caused by unicast routing table:
    def change_on_unicast_routing(self, interface_change=False):
        self.change_rpf(interface_change)

    def change_rpf(self, interface_change=False):
        current_rpf = self.get_neighbor_RPF()
        if interface_change or self._last_rpf != current_rpf:
            self._join_state.RPFnbrChangesNotOnAssert(self, self._last_rpf, current_rpf)
            self._last_rpf = current_rpf


    ####################################################################
    #Override
    def is_forwarding(self):
        return False

    # If new/reset neighbor is RPF neighbor
    def new_or_reset_neighbor(self, neighbor_ip):
        if neighbor_ip == self.get_neighbor_RPF():
            self._join_state.RPFnbrGenIDChanges(self)
        if neighbor_ip == self._assert_winner_metric._ip_address:
            self._assert_state.winnerLivelinessTimerExpires_GenIDChanged(self)

    #Override
    def delete(self, change_type_interface=False):
        self.socket_is_enabled = False
        self.socket_pkt.close()
        super().delete(change_type_interface)
        self.clear_assert_timer()
        self.clear_join_timer()

        # Clear Graft/Prune State:
        self._join_state = None

    def is_downstream(self):
        return False

    @property
    def t_override(self):
        oi = self.get_interface()._override_interval
        return random.uniform(0, oi)
