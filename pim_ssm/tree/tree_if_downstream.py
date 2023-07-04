from threading import Timer
from CustomTimer.RemainingTimer import RemainingTimer
from .downstream_join import DownstreamState, DownstreamStateABS
from .tree_interface import TreeInterface
import logging
import Main

class TreeInterfaceDownstream(TreeInterface):
    LOGGER = logging.getLogger('pim.KernelEntry.DownstreamInterface')

    def __init__(self, kernel_entry, interface_id):
        extra_dict_logger = kernel_entry.kernel_entry_logger.extra.copy()
        extra_dict_logger['vif'] = interface_id
        extra_dict_logger['interfacename'] = Main.kernel.vif_index_to_name_dic[interface_id]
        logger = logging.LoggerAdapter(TreeInterfaceDownstream.LOGGER, extra_dict_logger)
        TreeInterface.__init__(self, kernel_entry, interface_id, logger)
        self.logger.debug('Created DownstreamInterface')
        self._join_state = DownstreamState.NoInfo
        self.join_prune_logger.debug('Downstream state transitions to ' + str(self._join_state))

    ##########################################
    # Set state
    ##########################################
    def set_join_state(self, new_state: DownstreamStateABS):
        with self.get_state_lock():
            if new_state != self._join_state:
                self._join_state = new_state
                self.join_prune_logger.debug('Downstream state transitions to ' + str(new_state))

                self.change_tree()
                self.evaluate_ingroup()

    ##########################################
    # Check timers
    ##########################################
    def is_prune_pending_timer_running(self):
        return self._prune_pending_timer is not None and self._prune_pending_timer.is_alive()

    def is_join_timer_running(self):
        return self._join_timer is not None and self._join_timer.is_alive()

    def remaining_join_timer(self):
        return 0 if not self._join_timer else self._join_timer.time_remaining()

    ##########################################
    # Set timers
    ##########################################
    def set_prune_pending_timer(self, time):
        self.clear_prune_pending_timer()
        self._prune_pending_timer = Timer(time, self.prune_pending_timeout)
        self._prune_pending_timer.start()

    def clear_prune_pending_timer(self):
        if self._prune_pending_timer is not None:
            self._prune_pending_timer.cancel()

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
    def prune_pending_timeout(self):
        self._join_state.PPTexpires(self)

    def join_timeout(self):
        self._join_state.JTexpires(self)

    ###########################################
    # Recv packets
    ###########################################
    def recv_data_msg(self):
        if self.could_assert():
            self._assert_state.receivedDataFromDownstreamIf(self)

    # Override
    def recv_prune_msg(self, upstream_neighbor_address, holdtime):
        super().recv_prune_msg(upstream_neighbor_address, holdtime)

        if upstream_neighbor_address == self.get_ip():
            self._join_state.receivedPrune(self, holdtime)

    # Override
    def recv_join_msg(self, upstream_neighbor_address, holdtime):
        super().recv_join_msg(upstream_neighbor_address, holdtime)

        if upstream_neighbor_address == self.get_ip():
            self.set_receceived_join_holdtime(holdtime)
            self._join_state.receivedJoin(self, holdtime)

    ##########################################################

    # Override
    def is_forwarding(self):
        return ((self.has_neighbors() and self.is_join()) or self.pim_include()) and not self.lost_assert()

    def is_join(self):
        return self._join_state == DownstreamState.Join or self._join_state ==DownstreamState.PrunePending

    def new_or_reset_neighbor_info(self, neighbor_ip):
        return
    def new_or_reset_neighbor(self, neighbor_ip):
        return

    # Override
    def delete(self, change_type_interface=False):
        super().delete(change_type_interface)
        self.clear_assert_timer()
        self.clear_join_timer()
        self.clear_prune_pending_timer()

    def is_downstream(self):
        return True
