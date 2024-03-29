from tree.tree_if_upstream import TreeInterfaceUpstream
from tree.tree_if_downstream import TreeInterfaceDownstream
from .tree_interface import TreeInterface
from threading import Timer, Lock, RLock
from tree.metric import AssertMetric
import UnicastRouting
from time import time
import Main
import logging

class KernelEntry:
    TREE_TIMEOUT = 180
    KERNEL_LOGGER = logging.getLogger('pim.KernelEntry')

    def __init__(self, source_ip: str, group_ip: str):
        self.kernel_entry_logger = logging.LoggerAdapter(KernelEntry.KERNEL_LOGGER, {'tree': '(' + source_ip + ',' + group_ip + ')'})
        self.kernel_entry_logger.debug('Create KernelEntry')

        self.source_ip = source_ip
        self.group_ip = group_ip

        # OBTAIN UNICAST ROUTING INFORMATION###################################################
        (metric_administrative_distance, metric_cost, rpf_node, root_if, mask) = \
            UnicastRouting.get_unicast_info(source_ip)
        if root_if is None:
            raise Exception
        self.rpf_node = rpf_node

        # (S,G) starts IG state
        self._was_olist_null = False

        # Locks
        self._multicast_change = Lock()
        self._lock_test2 = RLock()
        self.CHANGE_STATE_LOCK = RLock()

        # decide inbound interface based on rpf check
        self.inbound_interface_index = root_if

        self.interface_state = {}  # Dict[int, TreeInterface]
        with self.CHANGE_STATE_LOCK:
            for i in Main.kernel.vif_index_to_name_dic.keys():
                print("In creating tree interface\n")
                try:
                    if i == self.inbound_interface_index:
                        self.interface_state[i] = TreeInterfaceUpstream(self, i)
                        print("Done creating upstream tree interface\n")
                    else:
                        self.interface_state[i] = TreeInterfaceDownstream(self, i)
                        print("Done creating downstream tree interface\n")
                except:
                    import traceback
                    print(traceback.print_exc())
                    continue

        self.change()
        self.evaluate_olist_change()
        print('Tree created')

    def get_inbound_interface_index(self):
        return self.inbound_interface_index

    def get_outbound_interfaces_indexes(self):
        outbound_indexes = [0]*Main.kernel.MAXVIFS
        for (index, state) in self.interface_state.items():
            outbound_indexes[index] = state.is_forwarding() and index != self.inbound_interface_index
        return outbound_indexes

    ################################################
    # Receive (S,G) data packets or control packets
    ################################################
    def recv_data_msg(self, index):
        print("recv data")
        self.interface_state[index].recv_data_msg()

    def recv_assert_msg(self, index, packet):
        pkt_assert = packet.payload.payload
        metric = pkt_assert.metric
        metric_preference = pkt_assert.metric_preference
        assert_sender_ip = packet.ip_header.ip_src
        print("recv assert from: ", assert_sender_ip)

        received_metric = AssertMetric(metric_preference=metric_preference, route_metric=metric, ip_address=assert_sender_ip)
        self.interface_state[index].recv_assert_msg(received_metric)

    def recv_prune_msg(self, index, packet):
        print("recv prune msg")
        holdtime = packet.payload.payload.hold_time
        upstream_neighbor_address = packet.payload.payload.upstream_neighbor_address
        self.interface_state[index].recv_prune_msg(upstream_neighbor_address=upstream_neighbor_address, holdtime=holdtime)

    def recv_join_msg(self, index, packet):
        print("recv join msg")
        holdtime = packet.payload.payload.hold_time
        upstream_neighbor_address = packet.payload.payload.upstream_neighbor_address
        self.interface_state[index].recv_join_msg(upstream_neighbor_address, holdtime=holdtime)

    def recv_graft_msg(self, index, packet):
        print("recv graft msg")
        upstream_neighbor_address = packet.payload.payload.upstream_neighbor_address
        source_ip = packet.ip_header.ip_src
        self.interface_state[index].recv_graft_msg(upstream_neighbor_address, source_ip)

    def igmp_update(self, index, has_members):
        print("igmp update")
        self.interface_state[index].notify_igmp(has_members)

    ###############################################################
    # Unicast Changes to RPF
    ###############################################################
    def network_update(self):
        # TODO TALVEZ OUTRO LOCK PARA BLOQUEAR ENTRADA DE PACOTES
        with self.CHANGE_STATE_LOCK:

            (metric_administrative_distance, metric_cost, rpf_node, new_inbound_interface_index, _) = \
                UnicastRouting.get_unicast_info(self.source_ip)

            if new_inbound_interface_index is None:
                self.delete()
                return
            if new_inbound_interface_index != self.inbound_interface_index:
                self.rpf_node = rpf_node

                # get old interfaces
                old_upstream_interface = self.interface_state.get(self.inbound_interface_index, None)
                old_downstream_interface = self.interface_state.get(new_inbound_interface_index, None)

                # change type of interfaces
                if self.inbound_interface_index is not None:
                    new_downstream_interface = TreeInterfaceDownstream(self, self.inbound_interface_index)
                    self.interface_state[self.inbound_interface_index] = new_downstream_interface
                new_upstream_interface = None
                if new_inbound_interface_index is not None:
                    new_upstream_interface = TreeInterfaceUpstream(self, new_inbound_interface_index)
                    self.interface_state[new_inbound_interface_index] = new_upstream_interface
                self.inbound_interface_index = new_inbound_interface_index

                # remove old interfaces
                if old_upstream_interface is not None:
                    print("\n\nHEREEEE DELETE OLD UPSTREAM: NEED DO SEND ASSERTCANCEL\n\n")
                    old_upstream_interface.delete(change_type_interface=True)
                if old_downstream_interface is not None:
                    old_downstream_interface.delete(change_type_interface=True)

                # atualizar tabela de encaminhamento multicast
                #self._was_olist_null = False
                self.change()
                self.evaluate_olist_change()
                if new_upstream_interface is not None:
                    new_upstream_interface.change_on_unicast_routing(interface_change=True)
            elif self.rpf_node != rpf_node:
                self.rpf_node = rpf_node
                self.interface_state[self.inbound_interface_index].change_on_unicast_routing()
            else:
                outbound_interfaces = self.get_outbound_interfaces_indexes()
                for out_i in outbound_interfaces:
                    self.interface_state[out_i].my_assert_metric_changed()



    # check if add/removal of neighbors from interface afects olist and forward/prune state of interface
    def change_at_number_of_neighbors(self):
        with self.CHANGE_STATE_LOCK:
            self.change()
            self.evaluate_olist_change()

    def new_or_reset_neighbor_info(self, if_index, neighbor_ip):
        # todo maybe lock de interfaces
        return self.interface_state[if_index].new_or_reset_neighbor_info(neighbor_ip)

    def new_or_reset_neighbor(self, if_index, neighbor_ip):
        # todo maybe lock de interfaces
        self.interface_state[if_index].new_or_reset_neighbor(neighbor_ip)
    
    def dr_changed(self, if_index):
        # todo maybe lock de interfaces
        self.interface_state[if_index].dr_changed()

    def is_olist_null(self):
        for interface in self.interface_state.values():
            if interface.is_forwarding():
                return False
        return True

    def evaluate_olist_change(self):
        with self._lock_test2:
            is_olist_null = self.is_olist_null()

            if self._was_olist_null != is_olist_null:
                if is_olist_null:
                    self.interface_state[self.inbound_interface_index].olist_is_null()
                else:
                    self.interface_state[self.inbound_interface_index].olist_is_not_null()

                self._was_olist_null = is_olist_null

    def get_source(self):
        return self.source_ip

    def get_group(self):
        return self.group_ip

    def change(self):
        with self._multicast_change:
            if self.inbound_interface_index is not None:
                Main.kernel.set_multicast_route(self)

    def delete(self):
        with self._multicast_change:
            for state in self.interface_state.values():
                state.delete()

            Main.kernel.remove_multicast_route(self)


    ######################################
    # Interface change
    #######################################
    def new_interface(self, index):
        with self.CHANGE_STATE_LOCK:
            self.interface_state[index] = TreeInterfaceDownstream(self, index)
            self.change()
            self.evaluate_olist_change()

    def remove_interface(self, index):
        with self.CHANGE_STATE_LOCK:
            #check if removed interface is root interface
            if self.inbound_interface_index == index:
                self.delete()
            elif index in self.interface_state:
                self.interface_state.pop(index).delete()
                self.change()
                self.evaluate_olist_change()
