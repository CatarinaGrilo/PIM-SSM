from abc import ABCMeta, abstractmethod

from tree import globals as pim_globals
from utils import TYPE_CHECKING
if TYPE_CHECKING:
    from .tree_if_downstream import TreeInterfaceDownstream

class DownstreamStateABS(metaclass=ABCMeta):
    @staticmethod
    @abstractmethod
    def receivedPrune(interface: "TreeInterfaceDownstream", holdtime):
        """
        Receive Prune(S,G)

        @type interface: Downstream
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def receivedJoin(interface: "TreeInterfaceDownstream", holdtime):
        """
        Receive Join(S,G)

        @type interface: Downstream
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def PPTexpires(interface: "TreeInterfaceDownstream"):
        """
        PPT(S,G) Expires

        @type interface: Downstream
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def JTexpires(interface: "TreeInterfaceDownstream"):
        """
        PT(S,G) Expires

        @type interface: Downstream
        """
        raise NotImplementedError()

    def __str__(self):
        return "Downstream." + self.__class__.__name__

class NoInfo(DownstreamStateABS):
    '''
    NoInfo(NI)
    The interface has no (S,G) Join state and no (S,G) timers
    running.
    '''

    @staticmethod
    def receivedPrune(interface: "TreeInterfaceDownstream", holdtime):
        """
        Receive Prune(S,G)

        @type interface: TreeInterfaceDownstreamDownstream
        """
        # Do nothing
        interface.join_prune_logger.debug("receivedPrune, NI -> NI")

    @staticmethod
    def receivedJoin(interface: "TreeInterfaceDownstream", holdtime):
        """
        Receive Join(S,G)

        @type interface: TreeInterfaceDownstreamDownstream
        """
        interface.join_prune_logger.debug("receivedJoin, NI -> J")
        interface.set_join_state(DownstreamState.Join)
        interface.set_join_timer(holdtime)

    @staticmethod
    def PPTexpires(interface: "TreeInterfaceDownstream"):
        """
        PPT(S,G) Expires

        @type interface: TreeInterfaceDownstreamDownstream
        """
        #"PPTexpires in state NI" - this should not happen
        return

    @staticmethod
    def JTexpires(interface: "TreeInterfaceDownstream"):
        """
        PT(S,G) Expires

        @type interface: TreeInterfaceDownstreamDownstream
        """
        #"JTexpires in state NI" - this should not happen
        return

    def __str__(self):
        return "NoInfo"

class PrunePending(DownstreamStateABS):
    '''
    PrunePending(PP)
    The router has received a Prune(S,G) on this interface from a
    downstream neighbor and is waiting to see whether the prune will
    be overridden by another downstream router. For forwarding
    purposes, the PrunePending state functions exactly like the
    Join state.
    '''

    @staticmethod
    def receivedPrune(interface: "TreeInterfaceDownstream", holdtime):
        """
        Receive Prune(S,G)

        @type interface: TreeInterfaceDownstreamDownstream
        """
        interface.join_prune_logger.debug('receivedPrune, PP -> PP')


    @staticmethod
    def receivedJoin(interface: "TreeInterfaceDownstream", holdtime):
        """
        Receive Join(S,G)

        @type interface: TreeInterfaceDownstreamDownstream
        """
        interface.join_prune_logger.debug('receivedJoin, PP -> J')

        interface.clear_prune_pending_timer()

        interface.set_join_timer(max(interface.get_received_join_holdtime(), holdtime))

        interface.set_join_state(DownstreamState.Join)

    @staticmethod
    def PPTexpires(interface: "TreeInterfaceDownstream"):
        """
        PPT(S,G) Expires

        @type interface: TreeInterfaceDownstreamDownstream
        """
        interface.join_prune_logger.debug('PPTexpires, PP -> NI')
        interface.set_join_state(DownstreamState.NoInfo)
        if not interface.could_assert():
            interface._assert_state.couldAssertIsNowFalse(interface)
        if not interface.assert_tracking_desired():
            interface._assert_state.assertTrackingDesiredIsNowFalse(interface)

        if len(interface.get_interface().neighbors) > 1:
            interface.send_pruneecho()

    @staticmethod
    def JTexpires(interface: "TreeInterfaceDownstream"):
        """
        PT(S,G) Expires

        @type interface: TreeInterfaceDownstreamDownstream
        """
        interface.join_prune_logger.debug('JTexpires, PP -> NI')
        interface.set_join_state(DownstreamState.NoInfo)
        if not interface.could_assert():
            interface._assert_state.couldAssertIsNowFalse(interface)
        if not interface.assert_tracking_desired():
            interface._assert_state.assertTrackingDesiredIsNowFalse(interface)

class Join(DownstreamStateABS):
    '''
    Join (J)
    The interface has (S,G) Join state, which will cause the
    router to forward packets from S destined for G from this
    interface if the (S,G) state is active (the SPTbit is set)
    except if the router lost an assert on this interface.
    '''

    @staticmethod
    def receivedPrune(interface: "TreeInterfaceDownstream", holdtime):
        """
        Receive Prune(S,G)

        @type interface: TreeInterfaceDownstreamDownstream
        """
        interface.join_prune_logger.debug('receivedPrune, J -> PP')
        interface.set_join_state(DownstreamState.PrunePending)

        time = 0
        if len(interface.get_interface().neighbors) > 1:
            time = pim_globals.JP_OVERRIDE_INTERVAL
        interface.set_prune_pending_timer(time)

    @staticmethod
    def receivedJoin(interface: "TreeInterfaceDownstream", holdtime):
        """
        Receive Join(S,G)

        @type interface: TreeInterfaceDownstreamDownstream
        """
        interface.join_prune_logger.debug('receivedJoin, J -> J')

        interface.set_join_state(DownstreamState.Join)
        interface.set_join_timer(max(interface.get_received_join_holdtime(), holdtime))

    @staticmethod
    def PPTexpires(interface: "TreeInterfaceDownstream"):
        """
        PPT(S,G) Expires

        @type interface: TreeInterfaceDownstreamDownstream
        """
        # "PPTexpires in state J" - this should not happen
        return

    @staticmethod
    def JTexpires(interface: "TreeInterfaceDownstream"):
        """
        PT(S,G) Expires

        @type interface: TreeInterfaceDownstreamDownstream
        """
        interface.join_prune_logger.debug('JTexpires, J -> NI')
        interface.set_join_state(DownstreamState.NoInfo)
        if not interface.could_assert():
            interface._assert_state.couldAssertIsNowFalse(interface)
        if not interface.assert_tracking_desired():
            interface._assert_state.assertTrackingDesiredIsNowFalse(interface)

    def __str__(self):
        return "Join"

class DownstreamState():
    NoInfo = NoInfo()
    Join = Join()
    PrunePending = PrunePending()
