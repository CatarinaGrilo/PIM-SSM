import ipaddress
import socket
from threading import RLock

from utils import if_indextoname
from pyroute2 import IPDB

routing = {} # KEY : des_ip, VALUE : (metric_administrative_distance, metric_cost, rpf_node, rpf_if, mask)

def get_route(ip_dst: str):
    return UnicastRouting.get_route(ip_dst)


def get_metric(ip_dst: str):
    return UnicastRouting.get_metric(ip_dst)


def check_rpf(ip_dst):
    return UnicastRouting.check_rpf(ip_dst)


def get_unicast_info(ip_dst):
    return UnicastRouting.get_unicast_info(ip_dst)


class UnicastRouting(object):
    ipdb = None
    lock = RLock()

    def __init__(self):
        UnicastRouting.ipdb = IPDB()
        self._ipdb = UnicastRouting.ipdb
        self._ipdb.register_callback(UnicastRouting.unicast_changes, mode="post")



    # get metrics (routing preference and cost) to IP ip_dst
    @staticmethod
    def get_metric(ip_dst: str):
        (metric_administrative_distance, metric_cost, _, _, mask) = UnicastRouting.get_unicast_info(ip_dst)
        return (metric_administrative_distance, metric_cost, mask)

    # get output interface IP, used to send data to IP ip_dst
    # (root interface IP to ip_dst)
    @staticmethod
    def check_rpf(ip_dst):
        # vif index of rpf interface
        return UnicastRouting.get_unicast_info(ip_dst)[3]

    @staticmethod
    def get_route(ip_dst: str):
        """
        Get route from the unicast routing table regarding the entry of IP ip_dst
        """
        ip_bytes = socket.inet_aton(ip_dst)
        ip_int = int.from_bytes(ip_bytes, byteorder='big')
        info = None
        with UnicastRouting.lock:
            ipdb = UnicastRouting.ipdb # type:IPDB

            for mask_len in range(32, 0, -1):
                ip_bytes = (ip_int & (0xFFFFFFFF << (32 - mask_len))).to_bytes(4, "big")
                ip_dst = socket.inet_ntoa(ip_bytes) + "/" + str(mask_len)
                #print(ip_dst)
                if ip_dst in ipdb.routes:
                    #print(info)
                    if ipdb.routes[ip_dst]['ipdb_scope'] != 'gc':
                        info = ipdb.routes[ip_dst]
                    break
                else:
                    continue
            if not info:
                #print("0.0.0.0/0")
                if "default" in ipdb.routes:
                    info = ipdb.routes["default"]
            #print(info)
            return info

    @staticmethod
    def get_unicast_info(ip_dst):

        if routing.get(ip_dst, None) is not None:
            #print(str(routing))
            #print("Source is on dic\n\n")
            return routing.get(ip_dst, None)
        else:
            #print("Source not on dic\n\n")
            metric_administrative_distance = 0xFFFFFFFF
            metric_cost = 0xFFFFFFFF
            rpf_node = ip_dst
            oif = None
            mask = 0
            with UnicastRouting.lock:
                unicast_route = UnicastRouting.get_route(ip_dst)
                if unicast_route is not None:
                    oif = unicast_route.get("oif")
                    next_hop = unicast_route["gateway"]
                    multipaths = unicast_route["multipath"]
                    #prefsrc = unicast_route.get("prefsrc")

                    #rpf_node = ip_dst if (next_hop is None and prefsrc is not None) else next_hop
                    rpf_node = next_hop if next_hop is not None else ip_dst
                    highest_ip = ipaddress.ip_address("0.0.0.0")
                    for m in multipaths:
                        if m["gateway"] is None:
                            oif = m.get('oif')
                            rpf_node = ip_dst
                            break
                        elif ipaddress.ip_address(m["gateway"]) > highest_ip:
                            highest_ip = ipaddress.ip_address(m["gateway"])
                            oif = m.get('oif')
                            rpf_node = m["gateway"]

                metric_administrative_distance = unicast_route["proto"]
                metric_cost = unicast_route["priority"]
                metric_cost = metric_cost if metric_cost is not None else 0
                mask = unicast_route["dst_len"]

            interface_name = None if oif is None else if_indextoname(int(oif))
            import Main
            rpf_if = Main.kernel.vif_name_to_index_dic.get(interface_name)
            routing[ip_dst] = (metric_administrative_distance, metric_cost, rpf_node, rpf_if, mask)
            return (metric_administrative_distance, metric_cost, rpf_node, rpf_if, mask)

    @staticmethod
    def unicast_changes(ipdb, msg, action):
        """
        Kernel notified about a change
        Verify the type of change and recheck all trees if necessary
        """
        #print("unicast change?")
        #print(action)
        UnicastRouting.lock.acquire()
        if action == "RTM_NEWROUTE" or action == "RTM_DELROUTE":
            #print(ipdb.routes)
            mask_len = msg["dst_len"]
            network_address = None
            attrs = msg["attrs"]
            #print(attrs)
            for (key, value) in attrs:
                #print((key, value))
                if key == "RTA_DST":
                    #print("BEFORE THE BREAK")
                    network_address = value
                    break
            if network_address is None:
                network_address = "0.0.0.0"
            #print(network_address)
            #print(mask_len)
            #print(network_address + "/" + str(mask_len))
            subnet = ipaddress.ip_network(network_address + "/" + str(mask_len))
            #print(str(subnet))
            routing.clear()
            UnicastRouting.lock.release()
            import Main
            print("Unicast changes")
            Main.kernel.notify_unicast_changes(subnet)
        else:
            UnicastRouting.lock.release()

    def stop(self):
        """
        No longer monitor unicast changes....
        Invoked whenver the protocol is stopped
        """
        if self._ipdb:
            self._ipdb.release()
        if UnicastRouting.ipdb:
            UnicastRouting.ipdb = None
