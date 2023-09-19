from abc import ABCMeta, abstractmethod

import tree.globals as pim_globals
from .metric import AssertMetric
from utils import TYPE_CHECKING
if TYPE_CHECKING:
    from .tree_if_downstream import TreeInterfaceDownstream


class AssertStateABC(metaclass=ABCMeta):
    @staticmethod
    @abstractmethod
    def receivedDataFromDownstreamIf(interface: "TreeInterfaceDownstream"):
        """
        An (S,G) Data packet received on downstream interface

        @type interface: TreeInterface
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def receivedInferiorMetricFromWinner(interface: "TreeInterfaceDownstream", metric):
        """
        Receive Inferior (Assert OR State Refresh) from Assert Winner

        @type interface: TreeInterface
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def receivedInferiorMetricFromNonWinner_couldAssertIsTrue(interface: "TreeInterfaceDownstream"):
        """
        Receive Inferior (Assert OR  State Refresh) from non-Assert Winner
        AND CouldAssert==TRUE

        @type interface: TreeInterface
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def receivedPreferedMetric(interface: "TreeInterfaceDownstream", better_metric):
        """
        Receive Preferred Assert OR State Refresh

        @type interface: TreeInterface
        @type better_metric: AssertMetric
        """
        raise NotImplementedError()
    
    def receivedAcceptableMetric(interface: "TreeInterfaceDownstream", received_metric):
        """
        Receive Preferred Assert OR State Refresh

        @type interface: TreeInterface
        @type better_metric: AssertMetric
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def assertTimerExpires(interface: "TreeInterfaceDownstream"):
        """
        AT(S,G) Expires

        @type interface: TreeInterface
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def couldAssertIsNowFalse(interface: "TreeInterfaceDownstream"):
        """
        CouldAssert -> FALSE

        @type interface: TreeInterface
        """
        raise NotImplementedError()


    @staticmethod
    @abstractmethod
    def winnerLivelinessTimerExpires_GenIDChanged(interface: "TreeInterfaceDownstream"):
        """
        Winner’s NLT(N,I) Expires

        @type interface: TreeInterface
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def receivedJoin(interface: "TreeInterfaceDownstream"):
        """
        Receive Prune(S,G), Join(S,G) or Graft(S,G)

        @type interface: TreeInterface
        """
        raise NotImplementedError()
    
    def assertTrackingDesiredIsNowFalse(interface: "TreeInterfaceDownstream"):
        """
        Assert Tracking Desired Is Now False

        @type interface: TreeInterface
        """
        raise NotImplementedError()
    
    def myAssertIsBetterThanAW(interface: "TreeInterfaceDownstream"):
        """
        My metric becomes better than the assert winner's metric

        @type interface: TreeInterface
        """
        raise NotImplementedError()


    def _sendAssert_setAT(interface: "TreeInterfaceDownstream", winner=False):
        if winner == True:
            interface.set_assert_timer(pim_globals.ASSERT_TIME-3)
        else:
            interface.set_assert_timer(pim_globals.ASSERT_TIME)
        interface.send_assert()


    # Override
    def __str__(self) -> str:
        return "AssertSM:" + self.__class__.__name__

class NoInfoState(AssertStateABC):
    '''
    NoInfoState (NI)
    This router has no (S,G) Assert state on interface I.
    '''

    @staticmethod
    def receivedDataFromDownstreamIf(interface: "TreeInterfaceDownstream"):
        """
        @type interface: TreeInterface
        """
        interface.assert_logger.debug('receivedDataFromDownstreamIf, NI -> W')

        interface.set_assert_winner_metric(interface.my_assert_metric())
        interface.set_assert_state(AssertState.Winner)
        NoInfoState._sendAssert_setAT(interface, True)

    @staticmethod
    def receivedInferiorMetricFromWinner(interface: "TreeInterfaceDownstream", metric):
        assert False, "this should never ocurr"

    @staticmethod
    def receivedInferiorMetricFromNonWinner_couldAssertIsTrue(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('receivedInferiorMetricFromNonWinner_couldAssertIsTrue, NI -> W')

        interface.set_assert_winner_metric(interface.my_assert_metric())
        interface.set_assert_state(AssertState.Winner)
        NoInfoState._sendAssert_setAT(interface, True)

    @staticmethod
    def receivedPreferedMetric(interface: "TreeInterfaceDownstream", better_metric):
        '''
        @type interface: TreeInterface
        '''
        if interface.assert_tracking_desired():
            interface.assert_logger.debug('receivedPreferedMetricAndAssTrDesIsTrue, NI -> L')
            interface.set_assert_winner_metric(better_metric)
            interface.set_assert_timer(pim_globals.ASSERT_TIME)
            interface.set_assert_state(AssertState.Loser)
    
    @staticmethod
    def receivedAcceptableMetric(interface: "TreeInterfaceDownstream", received_metric):
        '''
        @type interface: TreeInterface
        '''
        return

    @staticmethod
    def assertTimerExpires(interface: "TreeInterfaceDownstream"):
        assert False, "this should never ocurr"

    @staticmethod
    def couldAssertIsNowFalse(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('couldAssertIsNowFalse, NI -> NI')

    @staticmethod
    def winnerLivelinessTimerExpires_GenIDChanged(interface: "TreeInterfaceDownstream"):
        assert False, "this should never ocurr"

    @staticmethod
    def receivedJoin(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('receivedJoin, NI -> NI')

    @staticmethod
    def assertTrackingDesiredIsNowFalse(interface: "TreeInterfaceDownstream"):
        return
    
    @staticmethod
    def myAssertIsBetterThanAW(interface: "TreeInterfaceDownstream"):
        return

    def __str__(self) -> str:
        return "NoInfo"

class WinnerState(AssertStateABC):
    '''
    I am Assert Winner (W)
    This router has won an (S,G) Assert on interface I. It is now
    responsible for forwarding traffic from S destined for G via
    interface I.
    '''

    @staticmethod
    def receivedDataFromDownstreamIf(interface: "TreeInterfaceDownstream"):
        """
        @type interface: TreeInterface
        """
        interface.assert_logger.debug('receivedDataFromDownstreamIf, W -> W')
        WinnerState._sendAssert_setAT(interface, True)

    @staticmethod
    def receivedInferiorMetricFromWinner(interface: "TreeInterfaceDownstream", metric):
        assert False, "this should never ocurr"

    @staticmethod
    def receivedInferiorMetricFromNonWinner_couldAssertIsTrue(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('receivedInferiorMetricFromNonWinner_couldAssertIsTrue, W -> W')
        WinnerState._sendAssert_setAT(interface, True)

    @staticmethod
    def receivedPreferedMetric(interface: "TreeInterfaceDownstream", better_metric):
        '''
        @type better_metric: AssertMetric
        '''
        interface.assert_logger.debug('receivedPreferedMetric, W -> L')
        interface.set_assert_winner_metric(better_metric)
        interface.set_assert_timer(pim_globals.ASSERT_TIME)
        interface.set_assert_state(AssertState.Loser)
    
    @staticmethod
    def receivedAcceptableMetric(interface: "TreeInterfaceDownstream", received_metric):
        '''
        @type interface: TreeInterface
        '''
        return

    @staticmethod
    def assertTimerExpires(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('assertTimerExpires, W -> W')
        interface.set_assert_winner_metric(interface.my_assert_metric())
        WinnerState._sendAssert_setAT(interface, True)

    @staticmethod
    def couldAssertIsNowFalse(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('couldAssertIsNowFalse, W -> NI')
        interface.send_assert_cancel()
        interface.clear_assert_timer()
        interface.set_assert_winner_metric(AssertMetric.infinite_assert_metric())
        interface.set_assert_state(AssertState.NoInfo)

    @staticmethod
    def winnerLivelinessTimerExpires_GenIDChanged(interface: "TreeInterfaceDownstream"):
        assert False, "this should never ocurr"

    @staticmethod
    def receivedJoin(interface: "TreeInterfaceDownstream"):
        pass

    @staticmethod
    def assertTrackingDesiredIsNowFalse(interface: "TreeInterfaceDownstream"):
        return
    
    @staticmethod
    def myAssertIsBetterThanAW(interface: "TreeInterfaceDownstream"):
        return

    def __str__(self) -> str:
        return "Winner"

class LoserState(AssertStateABC):
    '''
    I am Assert Loser (L)
    This router has lost an (S,G) Assert on interface I. It must not
    forward packets from S destined for G onto interface I.
    '''

    @staticmethod
    def receivedDataFromDownstreamIf(interface: "TreeInterfaceDownstream"):
        """
        @type interface: TreeInterface
        """
        interface.assert_logger.debug('receivedDataFromDownstreamIf, L -> L')

    @staticmethod
    def receivedInferiorMetricFromWinner(interface: "TreeInterfaceDownstream", metric):
        interface.assert_logger.debug('receivedInferiorMetricFromWinner, L -> NI')

        if metric.is_better_than(interface.my_assert_metric()) and metric != AssertMetric():
            interface.assert_logger.debug('receivedInferiorMetricFromWinnerAndIsBetterThanMyMetric, L -> L')
            interface.set_assert_winner_metric(metric)
            interface.set_assert_timer(pim_globals.ASSERT_TIME)
        else:
            interface.assert_logger.debug('receivedInferiorMetricFromWinner, L -> NI')
            LoserState._to_NoInfo(interface)

    @staticmethod
    def receivedInferiorMetricFromNonWinner_couldAssertIsTrue(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('receivedInferiorMetricFromNonWinner_couldAssertIsTrue, L -> L')

    @staticmethod
    def receivedPreferedMetric(interface: "TreeInterfaceDownstream", better_metric):
        '''
        @type better_metric: AssertMetric
        '''
        interface.assert_logger.debug('receivedPreferedMetric, L -> L')
        interface.set_assert_winner_metric(better_metric)
        interface.set_assert_timer(pim_globals.ASSERT_TIME)
        interface.set_assert_state(AssertState.Loser)

    @staticmethod
    def receivedAcceptableMetric(interface: "TreeInterfaceDownstream", received_metric):
        '''
        @type interface: TreeInterface
        '''
        interface.assert_logger.debug('receivedAcceptableMetric, L -> L')
        interface.set_assert_winner_metric(received_metric)
        interface.set_assert_timer(pim_globals.ASSERT_TIME)
        interface.set_assert_state(AssertState.Loser)

    @staticmethod
    def assertTimerExpires(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('assertTimerExpires, L -> NI')
        LoserState._to_NoInfo(interface)

    @staticmethod
    def couldAssertIsNowFalse(interface: "TreeInterfaceDownstream"):
        return

    @staticmethod
    def winnerLivelinessTimerExpires_GenIDChanged(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('winnerLivelinessTimerExpires_GenIDChanged, L -> NI')
        LoserState._to_NoInfo(interface)

    @staticmethod
    def receivedJoin(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('receivedJoin, L -> NI')
        LoserState._to_NoInfo(interface)
    
    @staticmethod
    def assertTrackingDesiredIsNowFalse(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('assertTrackingDesiredIsNowFalse, L -> NI')
        LoserState._to_NoInfo(interface)

    @staticmethod
    def myAssertIsBetterThanAW(interface: "TreeInterfaceDownstream"):
        interface.assert_logger.debug('myAssertIsBetterThanAW, L -> NI')
        LoserState._to_NoInfo(interface)

    @staticmethod
    def _to_NoInfo(interface: "TreeInterfaceDownstream"):
        interface.clear_assert_timer()
        interface.set_assert_winner_metric(AssertMetric.infinite_assert_metric())
        interface.set_assert_state(AssertState.NoInfo)

    def __str__(self) -> str:
        return "Loser"

class AssertState():
    NoInfo = NoInfoState()
    Winner = WinnerState()
    Loser = LoserState()