from ipaddress import IPv4Address
from threading import Timer
from threading import Lock
import Main
from Packet.PacketIGMPHeader import PacketIGMPHeader
from Packet.PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from igmpv3.igmp_globals import GROUP_MEMBERSHIP_INTERVAL, MAX_RESPONSE_TIME_LAST_MEMBER_QUERY_INTERVAL
from igmpv3.RouterState import RouterState
# TODO: next line in comment for testing purpose.
#from InterfaceIGMP import InterfaceIGMP
from Packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
class GroupState:
    # Key: GroupIPAddress, Value: GroupState object
    # In RouterState.py --> self.group_state = {}

    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"

    def __init__(self, mc_ip_address, filter_mode, router_state: 'RouterState'):
        if not IPv4Address(mc_ip_address).is_multicast:
            raise ValueError('[ERROR-INFO]: ' + mc_ip_address + ' is not a multicast address')
        self.group_ip = mc_ip_address
        # lock
        self.lock = Lock()
        self.group_timer = None
        self.set_group_timer()
        self.filter_mode = filter_mode
        # Key: str ip_address, Value: Timer object
        self.source_addresses = {}
        self.router_state = router_state
        self.sources_in_risk_to_exclude = []
        # KernelEntry's instances to notify change of igmp state
        self.multicast_interface_state = []
        self.multicast_interface_state_lock = Lock()

    def add_sources(self, source: str):
        isAlready = False
        for i in self.source_addresses:
            if i == source:
                isAlready = True
                self.set_source_timer(i)
                break
        if isAlready == False:
            self.set_source_timer(source)

    #          #         #      */
    # TIMERS   #         #      */
    #          #         #      */
    def set_group_timer(self):
        """
        Set back to 0 the group timer
        """
        self.clear_group_timer()
        group_timer = Timer(
            MAX_RESPONSE_TIME_LAST_MEMBER_QUERY_INTERVAL, self.group_timeout)
        group_timer.start()
        self.group_timer = group_timer

    def clear_group_timer(self):
        """
        Stop group timer
        """
        if self.group_timer is not None:
            self.group_timer.cancel()
    
    def set_source_timer(self, source):
        """
        Set back to 0 the source timer
        """
        if source in self.source_addresses:
            self.clear_source_timer(source)
        source_timer = Timer(
            MAX_RESPONSE_TIME_LAST_MEMBER_QUERY_INTERVAL, self.source_timeout, [source])
        source_timer.start()
        self.source_addresses[source] = source_timer

    def clear_source_timer(self, source):
        """
        Stop source timer
        """
        if self.source_addresses[source] is not None:
            self.source_addresses[source].cancel()
            self.source_addresses[source] = None
            print("Timer down")
            print(source)

    def group_timeout(self):
        print("GROUP TIMEOUT")
        #print('risk: ', self.sources_in_risk_to_exclude)
        for source in self.sources_in_risk_to_exclude:
            #print('HERE1')
            if source in self.source_addresses:
                    #print('HERE2')
                    self.clear_source_timer(source)
                    self.source_addresses.pop(source)
                    self.sources_in_risk_to_exclude.remove(source)
                    self.notify_routing_remove(source)
        if len(self.source_addresses) == 0:
            self.filter_mode = GroupState.INCLUDE
        #if all source timers have expired => delete group 
        cntr = True
        for source in self.source_addresses:
            if self.source_addresses[source] != None:
                cntr = False
                break
        #print("lenght: ",len(self.source_addresses))
        if len(self.source_addresses) == 0 or cntr == False:
            self.remove()
            self.router_state.remove_group(self.group_ip)
            print("[INFO]: Group removed.")

    def source_timeout(self, source: str):
        a = "INFO: " + source + " source timeout"
        print(a)
        if self.filter_mode == GroupState.INCLUDE:
            #concludes that traffic from this source is no longer desired
            self.source_addresses.pop(source)
            self.notify_routing_remove(source)
            print("Source {} was removed from sources list of group {}.".format(source, self.group_ip))
        elif self.filter_mode == GroupState.EXCLUDE:
            self.source_addresses[source] = None
            print("Source {} will be removed if the group timer expires.". format(source))

    #          #         #      */
    # REPORT METHODS     #      */
    #          #         #      */
    def receive_v3_membership_report(self, source_addresses, operation_type):
        print("Got a Report")
        lst_ip = []
        for source in source_addresses:
            lst_ip.append(source.getAddress())
        src_ip = []
        for key in self.source_addresses.keys():
            src_ip.append(str(key))
        # Turns off the timer associated with the source.
        # When it receives a query with sources, the router
        # should expect an answer from hosts in a certain time.
        for source in lst_ip:
            if source in self.source_addresses:
                self.clear_source_timer(source)
                #print("here")
                #print(source)

        #INCLUDE | # ALLOW_NEW_SOURCES
        if int(operation_type) == 1 or int(operation_type) == 5: 
            print(operation_type)
            print("#INCLUDE | # ALLOW_NEW_SOURCES")
            if self.filter_mode == GroupState.INCLUDE:
                for s in source_addresses:
                    if s.getAddress() not in self.source_addresses:
                        self.add_sources(s.getAddress())
                        self.notify_routing_add(s.getAddress())
                    self.clear_source_timer(s.getAddress())
                    if s.getAddress() in self.sources_in_risk_to_exclude:
                        #print('source ADDRESS: type: ', s.getAddress(), type(s.getAddress()))
                        self.sources_in_risk_to_exclude.remove(s.getAddress())
            elif self.filter_mode == GroupState.EXCLUDE:
                for s in source_addresses:
                    if s.getAddress() in self.source_addresses:
                        self.clear_source_timer(s.getAddress())
                        self.source_addresses.pop(s.getAddress())
                        self.notify_routing_remove(s.getAddress())
        #EXCLUDE
        elif int(operation_type) == 2: 
            print("#EXCLUDE")
            if len(source_addresses) == 0:
                # EXCLUDE {}
                for s in self.source_addresses:
                    self.clear_source_timer(s)
                    self.source_addresses.pop(s)
                    self.notify_routing_remove(s.getAddress())
                self.filter_mode = GroupState.INCLUDE
            else:
                if self.filter_mode == GroupState.INCLUDE:
                    # EXCLUDE list minus what is common in both lists
                    lst3 = [value for value in src_ip if value in lst_ip]
                    load = list(set(lst_ip) - set(lst3))
                elif self.filter_mode == GroupState.EXCLUDE:
                    load = list(set([value for value in src_ip if value in lst_ip]))

                self.source_addresses = {}
                for s in load:
                    self.add_sources(s)
                    self.notify_routing_add(s.getAddress())
            self.clear_group_timer()
            self.filter_mode = GroupState.EXCLUDE
        # CHANGE_TO_INCLUDE
        elif int(operation_type) == 3:  
            print("# CHANGE_TO_INCLUDE")
            if self.filter_mode == GroupState.INCLUDE:
                for s in source_addresses:
                    self.add_sources(s.getAddress())
                #send a group and source specific query Q(G, A-B)
                data = PacketIGMPv3HeaderQuery(0, 0, 2, 125, self.group_ip)
                lst3 = [value for value in src_ip if value in lst_ip]
                load = list(set(lst_ip) - set(lst3))
                for s in load:
                    source = PacketIGMPMSourceAddress(s)
                    data.addSourceAddress(source)
                packet = PacketIGMPHeader(data)
                if self.router_state.interface_state == "Querier":
                    self.router_state.interface.send(packet.bytes(), self.group_ip)
                    print("[INFO]: A Query was sent.")
                
            if self.filter_mode == GroupState.EXCLUDE:
                for s in self.source_addresses:
                    if s in lst_ip:
                        self.source_addresses.pop(s)
                #send a group specific query Q(G)
                data = PacketIGMPv3HeaderQuery(0, 0, 2, 125, self.group_ip)
                packet = PacketIGMPHeader(data)
                if self.router_state.interface_state == "Querier":
                    self.router_state.interface.send(packet.bytes(), self.group_ip)
                    print("[INFO]: A Query was sent.")
            self.set_group_timer()
        # CHANGE_TO_EXCLUDE 
        elif int(operation_type) == 4:
            print("# CHANGE_TO_EXCLUDE ")
            # remove the intersection of both source lists from group state
            if self.filter_mode == GroupState.INCLUDE:
                lst3 = [value for value in src_ip if value in lst_ip]
                load = list(set(lst_ip) - set(lst3))
                for s in self.source_addresses:
                    if s in load:
                        self.source_addresses.pop(s)
                #send a group and source specific query Q(G, A*B)
                data = PacketIGMPv3HeaderQuery(0, 0, 2, 125, self.group_ip)
                for s in list(set(lst3)): # common sources
                    source = PacketIGMPMSourceAddress(s)
                    data.addSourceAddress(source)
                packet = PacketIGMPHeader(data)
                if self.router_state.interface_state == "Querier":
                    self.router_state.interface.send(packet.bytes(), self.group_ip)
                    print("[INFO]: A Query was sent.")
                self.set_group_timer()
                self.filter_mode == GroupState.EXCLUDE
            elif self.filter_mode == GroupState.EXCLUDE:
                srcs = []
                if len(source_addresses) == 0:
                    for s in self.source_addresses:
                        srcs.append(s)
                        self.clear_source_timer(s)
                        self.source_addresses.pop(s)
                    data = PacketIGMPv3HeaderQuery(0, 0, 2, 125, self.group_ip)
                    for s in list(srcs):
                        source = PacketIGMPMSourceAddress(s)
                        data.addSourceAddress(source)
                    packet = PacketIGMPHeader(data)
                    if self.router_state.interface_state == "Querier":
                        self.router_state.interface.send(packet.bytes(), self.group_ip)
                        print("[INFO]: A Query was sent.")
                else:
                    for s in source_addresses:
                        if s not in self.source_addresses:
                            self.add_sources(s)
                            srcs.append(s.getAddress())
                    data = PacketIGMPv3HeaderQuery(0, 0, 2, 125, self.group_ip)
                    for s in list(srcs):  
                        source = PacketIGMPMSourceAddress(s)
                        data.addSourceAddress(source)
                    packet = PacketIGMPHeader(data)
                    if self.router_state.interface_state == "Querier":
                        self.router_state.interface.send(packet.bytes(), self.group_ip)
                        print("[INFO]: A Query was sent.")
                self.set_group_timer()

        # BLOCK_OLD_SOURCES
        elif int(operation_type) == 6:
            print("# BLOCK_OLD_SOURCES")
            lst3 = [value for value in src_ip if value in lst_ip]
            #print('List: type:' ,lst3, type(lst3))
            load = list(set(lst_ip) - set(lst3))
            if self.router_state.interface_state == "Querier":
                #send a group and source specific query Q(G, A*B)
                data = PacketIGMPv3HeaderQuery(0, 0, 2, 125, self.group_ip)
                for s in lst3:  # common sources
                    source = PacketIGMPMSourceAddress(s)
                    data.addSourceAddress(source)
                    if s not in self.sources_in_risk_to_exclude:
                        #print('source type:', type(s))
                        self.sources_in_risk_to_exclude.append(s)
                packet = PacketIGMPHeader(data)
                self.router_state.interface.send(packet.bytes(), self.group_ip)
                print("[INFO]: A Query was sent.")
            for s in list(set(lst3)):  # common sources
                if s not in self.sources_in_risk_to_exclude:
                    self.sources_in_risk_to_exclude.append(s)
            # for source in lst_ip:
            #     if source in self.source_addresses:
            #         pass
            #         #self.source_addresses.pop(source)
            #         #self.notify_routing_remove(source)
            #print('risk: ', self.sources_in_risk_to_exclude)
            self.set_group_timer()

    #          #         #      */
    # QUERY METHODS      #      */
    #          #         #      */

    def receive_group_specific_query(self, max_response_time, source_adds: PacketIGMPMSourceAddress):
        self.set_group_timer()
        # Waits until it receives a report in which it is desired to receive from this group
        if len(source_adds) == 0:
            self.clear_group_timer()
            group_timer = Timer(MAX_RESPONSE_TIME_LAST_MEMBER_QUERY_INTERVAL, self.group_timeout)
            group_timer.start()
            self.group_timer = group_timer
        else:
            lst_ip = []
            for source in source_adds:
                lst_ip.append(source.getAddress())
                
            for s in lst_ip:
                if s in self.source_addresses:
                    self.clear_source_timer(s)
                    source_timer = Timer(MAX_RESPONSE_TIME_LAST_MEMBER_QUERY_INTERVAL, self.source_timeout, [s])
                    source_timer.start()
                    self.source_addresses[s] = source_timer
                else:
                    source_timer = Timer(MAX_RESPONSE_TIME_LAST_MEMBER_QUERY_INTERVAL, self.source_timeout, [s])
                    source_timer.start()
                    self.source_addresses[s] = source_timer
                    
            
    
    def remove(self):
        self.clear_group_timer
        for source in list(self.source_addresses):
            self.clear_source_timer(source)
            self.source_addresses.pop(source)


    ###########################################
    # Notify Routing
    ###########################################
    
    def notify_routing_add(self, source):
        """
        Notify kernel that IGMP considers to have hosts interested in this group
        """
        interest = True
        source_group = (source, self.group_ip)
        protocol_interface = self.get_interface()
        with self.multicast_interface_state_lock:
            #print("notify+", str(source))
            protocol_interface.receive_igmp(source_group, interest)

    def notify_routing_remove(self, source):
        """
        Notify kernel that IGMP considers to have not hosts interested in this group
        """
        interest = False
        source_group = (source, self.group_ip)
        protocol_interface = self.get_interface()
        with self.multicast_interface_state_lock:
            #print("notify-", str(source))
            protocol_interface.receive_igmp(source_group, interest)

    def add_multicast_routing_entry(self, kernel_entry):
        with self.multicast_interface_state_lock:
            print("In ADD MULTICAT ROUTING ENTRY IN IGMP\n\n")
            self.multicast_interface_state.append(kernel_entry)
            print("multicast interface state: ", self.multicast_interface_state)
            has = self.has_members()
            return has

    def remove_multicast_routing_entry(self, kernel_entry):
        with self.multicast_interface_state_lock:
            self.multicast_interface_state.remove(kernel_entry)

    def has_members(self):
        if self.source_addresses:
            print("True")
            return True
        else:
            print("False")
            return False
    
    def get_interface(self):
        """
        Get the InterfaceProtocol object regarding this physical interface
        """
        interface = Main.interfaces.get(self.router_state.interface.interface_name, None)
        return interface