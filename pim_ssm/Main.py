import netifaces
import time
from prettytable import PrettyTable
import sys
import logging, logging.handlers
from TestLogger import RootFilter

from Kernel import Kernel
import UnicastRouting

interfaces = {}  # interfaces with multicast routing enabled
igmp_interfaces = {}  # igmp interfaces
kernel = None
unicast_routing = None
logger = None

def add_pim_interface(interface_name):
    """
    Add a new interface to be controlled by PIM-SSM
    """
    kernel.create_pim_interface(interface_name=interface_name)

def add_igmp_interface(interface_name):
    """
    Add a new interface to be controlled by IGMP
    """
    kernel.create_igmp_interface(interface_name=interface_name)

def remove_interface(interface_name, pim=False, igmp=False):
    """
    Remove PIM-SSM/IGMP interface
    """
    kernel.remove_interface(interface_name, pim=pim, igmp=igmp)

def dr_priority(dr_priority):
    """
    Add a new interface to be controlled by PIM-SSM
    """
    interfaces_list = interfaces.values()
    for interface in interfaces_list:
        interface.DR_priority = int(dr_priority)
        interface.DR_election()

def list_neighbors():
    """
    List all neighbors in a human readable format
    """
    interfaces_list = interfaces.values()
    t = PrettyTable(['Interface', 'Neighbor IP', 'Hello Hold Time', "Generation ID", "DR priority", "Uptime"])
    check_time = time.time()
    for interface in interfaces_list:
        for neighbor in interface.get_neighbors():
            uptime = check_time - neighbor.time_of_last_update
            uptime = 0 if (uptime < 0) else uptime

            t.add_row(
                [interface.interface_name, neighbor.ip, neighbor.hello_hold_time, neighbor.generation_id, neighbor.DR_priority ,time.strftime("%H:%M:%S", time.gmtime(uptime))])
    print(t)
    return str(t)

def list_enabled_interfaces():
    """
    List all interfaces of the machine (enabled and not enabled for PIM-SSM and IGMP)
    """    
    t = PrettyTable(['Interface', 'IP', 'PIM/IGMP Enabled', 'IGMP State'])
    for interface in netifaces.interfaces():
        try:
            # TODO: fix same interface with multiple ips
            ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            pim_enabled = interface in interfaces
            igmp_enabled = interface in igmp_interfaces
            enabled = str(pim_enabled) + "/" + str(igmp_enabled)
            if igmp_enabled:
                state = igmp_interfaces[interface].interface_state.print_state()
            else:
                state = "-"
            t.add_row([interface, ip, enabled, state])
        except Exception:
            continue
    print(t)
    return str(t)

def list_state():
    """
    List IGMP and PIM-SSM state
    For IGMP list the state of each group, regarding each interface
    For HPIM-SM list all trees and state of each interface
    """
    state_text = "\nIGMPv3 State:\n" + list_igmp_state() +"\n\n" + "Multicast Routing State:\n" + list_routing_state()
    return state_text

def list_igmp_state():
    """
    List IGMP state (state of each group regarding each interface)
    """
    t = PrettyTable(['Interface', 'Group Address', 'Group State', 'Sources'])
    sources = " "
    for (interface_name, interface_obj) in list(igmp_interfaces.items()):
        interface_state = interface_obj.interface_state
        for key in interface_state.group_state:
            group_state_txt = interface_state.group_state[key].filter_mode
            for source in interface_state.group_state[key].source_addresses:
                sources += str(source) + "; "
            t.add_row([interface_name, key, group_state_txt, sources])
            sources = " "
    return str(t)

def list_routing_state():
    """
    List PIM-SSM state (all state machines of each tree, regarding each interface)
    """
    routing_entries = []
    for a in list(kernel.routing.values()):
        for b in list(a.values()):
            routing_entries.append(b)
    vif_indexes = kernel.vif_index_to_name_dic.keys()

    t = PrettyTable(['SourceIP', 'GroupIP', 'Interface', 'JoinState', 'AssertState', 'Am I DR?' ,'LocalMembership', "Is Forwarding?"])
    for entry in routing_entries:
        ip = entry.source_ip
        group = entry.group_ip
        upstream_if_index = entry.inbound_interface_index

        for index in vif_indexes:
            interface_state = entry.interface_state[index]
            interface_name = kernel.vif_index_to_name_dic[index]
            local_membership = type(interface_state._local_membership_state).__name__
            i_am_dr = interface_state.get_interface().i_am_dr()
            try:
                assert_state = type(interface_state._assert_state).__name__
                if index != upstream_if_index:
                    prune_state = type(interface_state._join_state).__name__
                    is_forwarding = interface_state.is_forwarding()
                else:
                    prune_state1 = type(interface_state._join_state).__name__
                    downstream_state = type(interface_state._downstream_join_state).__name__
                    prune_state = prune_state1 + '/' + downstream_state
                    is_forwarding = "upstream"
            except:
                prune_state = "-"
                assert_state = "-"
                is_forwarding = "-"

            t.add_row([ip, group, interface_name, prune_state, assert_state, i_am_dr, local_membership, is_forwarding])
    return str(t)

def stop():
    """
    Stop process
    """
    remove_interface("*", pim=True, igmp=True)
    kernel.exit()
    unicast_routing.stop()

def test(router_name, server_logger_ip):
    """
    Test setting.... Used to send logs to a remote server
    """
    global logger
    socketHandler = logging.handlers.SocketHandler(server_logger_ip,
                                                   logging.handlers.DEFAULT_TCP_LOGGING_PORT)
    # don't bother with a formatter, since a socket handler sends the event as
    # an unformatted pickle
    socketHandler.addFilter(RootFilter(router_name))
    logger.addHandler(socketHandler)

def main():
    # logging
    global logger
    logger = logging.getLogger('pim')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler(sys.stdout))
    
    global kernel
    kernel = Kernel()

    global unicast_routing
    unicast_routing = UnicastRouting.UnicastRouting()

    global interfaces
    global igmp_interfaces
    interfaces = kernel.pim_interface
    igmp_interfaces = kernel.igmp_interface
