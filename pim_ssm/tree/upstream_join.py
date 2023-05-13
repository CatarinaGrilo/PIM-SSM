from abc import ABCMeta, abstractmethod
from tree import globals as pim_globals
from utils import TYPE_CHECKING
if TYPE_CHECKING:
    from .tree_if_upstream import TreeInterfaceUpstream

class UpstreamStateABC(metaclass=ABCMeta):
    @staticmethod
    @abstractmethod
    def JoinDesired(interface: "TreeInterfaceUpstream", interest):
        """
        Join Desired(S,G)

        @type interface: TreeInterfaceUpstream
        """
        raise NotImplementedError()
    
    @staticmethod
    @abstractmethod
    def seeJoinToRPFnbr(interface: "TreeInterfaceUpstream"):
        """
        See Join(S,G) to RPF’(S)

        @type interface: Upstream
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def seePruneToRPFnbr(interface: "TreeInterfaceUpstream"):
        """
        See Prune(S,G)

        @type interface: Upstream
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def JTexpires(interface: "TreeInterfaceUpstream"):
        """
        OT(S,G) Expires

        @type interface: Upstream
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def RPFnbrChangesNotOnAssert(interface: "TreeInterfaceUpstream", last_rpf, current_rpf):
        """
        RPF’(S) Changes AND
        olist(S,G) != NULL AND
        S not directly connected

        @type interface: Upstream
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def RPFnbrGenIDChanges(interface: "TreeInterfaceUpstream"):
        """
        RPF’(S) Changes AND
        olist(S,G) == NULL

        @type interface: Upstream
        """
        raise NotImplementedError()
    
    @staticmethod
    @abstractmethod
    def RPFnbrChangesOnAssert(interface: "TreeInterfaceUpstream"):
        """
        RPF’(S) Changes AND
        olist(S,G) == NULL

        @type interface: Upstream
        """
        raise NotImplementedError()
    
    def __str__(self):
        return "Upstream." + self.__class__.__name__

class Joined(UpstreamStateABC):
    """
    Joined (J)
    The downstream state machines and local membership information
    indicate that the router should join the shortest-path tree for
    this (S,G).
    """

    @staticmethod
    def JoinDesired(interface: "TreeInterfaceUpstream", interest):
        """
        Join Desired(S,G)

        @type interface: TreeInterfaceUpstream
        """
        if interest == False:
            interface.join_prune_logger.debug('JoinDesired, J -> NJ')
            interface.set_state(UpstreamState.NotJoined)
            interface.send_prune()
            interface.clear_join_timer()

    @staticmethod
    def seeJoinToRPFnbr(interface: "TreeInterfaceUpstream"):
        """
        See Join(S,G) to RPF’(S)

        @type interface: TreeInterfaceUpstream
        """
        interface.join_prune_logger.debug('seeJoinToRPFnbr, J -> J')
        t_joinsuppress = min(interface.get_received_join_holdtime(), pim_globals.t_suppressed()) 
        if interface.remaining_join_timer() < t_joinsuppress:
            interface.set_join_timer(time=t_joinsuppress)

    @staticmethod
    def seePruneToRPFnbr(interface: "TreeInterfaceUpstream"):
        """
        See Prune(S,G) to RPF’(S)

        @type interface: TreeInterfaceUpstream
        """
        interface.join_prune_logger.debug('seePruneToRPFnbr, J -> J')
        if interface.remaining_join_timer() > pim_globals.JP_OVERRIDE_INTERVAL:
            interface.set_join_timer(time=pim_globals.JP_OVERRIDE_INTERVAL)

    @staticmethod
    def JTexpires(interface: "TreeInterfaceUpstream"):
        """
        OT(S,G) Expires

        @type interface: TreeInterfaceUpstream
        """
        interface.join_prune_logger.debug('JTexpires, J -> J')
        if not interface.is_S_directly_conn():
            interface.send_join()
            interface.set_join_timer(time=pim_globals.T_PERIODIC)

    @staticmethod
    def RPFnbrChangesNotOnAssert(interface: "TreeInterfaceUpstream", last_rpf, current_rpf):
        """
        RPF’(S) Changes AND
        olist(S,G) != NULL AND
        S not directly connected

        @type interface: TreeInterfaceUpstream
        """
        if not interface.is_S_directly_conn():
            interface.join_prune_logger.debug('RPFnbrChangesNotOnAssert, J -> J')
            interface.send_prune(last_rpf)
            interface.send_join(current_rpf)
            interface.set_join_timer(time=pim_globals.T_PERIODIC)

    @staticmethod
    def RPFnbrGenIDChanges(interface: "TreeInterfaceUpstream"):
        """
        RPF’(S) Changes AND
        olist(S,G) == NULL

        @type interface: TreeInterfaceUpstream
        """
        interface.join_prune_logger.debug('RPFnbrGenIDChanges, J -> J')
        if interface.remaining_join_timer() > pim_globals.JP_OVERRIDE_INTERVAL:
            interface.set_join_timer(time=pim_globals.JP_OVERRIDE_INTERVAL)


    @staticmethod
    def RPFnbrChangesOnAssert(interface: "TreeInterfaceUpstream"):
        """
        RPF’(S) Changes AND
        olist(S,G) == NULL

        @type interface: TreeInterfaceUpstream
        """
        interface.join_prune_logger.debug('RPFnbrChangesOnAssert, J -> J')
        print(str(interface.remaining_join_timer()))
        if interface.remaining_join_timer() > pim_globals.JP_OVERRIDE_INTERVAL:
            interface.set_join_timer(time=pim_globals.JP_OVERRIDE_INTERVAL)


    def __str__(self):
        return "Joined"


class NotJoined(UpstreamStateABC):
    '''
    Not Joined (NJ)
    The downstream state machines and local membership information do
    not indicate that the router needs to join the shortest-path tree
    for this (S,G).
    '''

    @staticmethod
    def JoinDesired(interface: "TreeInterfaceUpstream", interest):
        """
        Join Desired (S,G)

        @type interface: TreeInterfaceUpstream
        """
        if interest == True:
            interface.join_prune_logger.debug('JoinDesired, NJ -> J')
            interface.set_state(UpstreamState.Joined)
            interface.send_join()
            interface.set_join_timer(time=pim_globals.T_PERIODIC)

    @staticmethod
    def seeJoinToRPFnbr(interface: "TreeInterfaceUpstream"):
        """
        See Join(S,G) to RPF’(S)

        @type interface: TreeInterfaceUpstream
        """
        # Do nothing
        return

    @staticmethod
    def seePruneToRPFnbr(interface: "TreeInterfaceUpstream"):
        """
        See Prune(S,G)

        @type interface: TreeInterfaceUpstream
        """
        # Do nothing
        return
    
    @staticmethod
    def JTexpires(interface: "TreeInterfaceUpstream"):
        """
        OT(S,G) Expires

        @type interface: TreeInterfaceUpstream
        """
        # Do nothing
        return

    @staticmethod
    def RPFnbrChangesNotOnAssert(interface: "TreeInterfaceUpstream", last_rpf, current_rpf):
        """
        RPF’(S) Changes AND
        olist(S,G) != NULL AND
        S not directly connected

        @type interface: TreeInterfaceUpstream
        """
        # Do nothing
        return

    @staticmethod
    def RPFnbrGenIDChanges(interface: "TreeInterfaceUpstream"):
        """
        RPF’(S) Changes AND
        olist(S,G) == NULL

        @type interface: TreeInterfaceUpstream
        """
        # Do nothing
        return

    @staticmethod
    def RPFnbrChangesOnAssert(interface: "TreeInterfaceUpstream"):
        """
        RPF’(S) Changes AND
        olist(S,G) == NULL

        @type interface: TreeInterfaceUpstream
        """
        # Do nothing
        return

    def __str__(self):
        return "Not Joined"


class UpstreamState():
    Joined = Joined()
    NotJoined = NotJoined()
