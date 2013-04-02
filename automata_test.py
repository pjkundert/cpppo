import collections
import logging
import sys
import timeit

import automata

logging.basicConfig( level=logging.DEBUG, datefmt='%m-%d %H:%M'  ,
    format='%(asctime)s.%(msecs).3s %(name)-6.6s %(levelname)-6.6s %(funcName)-10.10s %(message)s' )
_log				= logging.getLogger()
_lognot				= _log.level-1

def accept_any( i ):
    return True

def test_logging():
    # Test lazy log message evaluation, ensuring it is at least an order of
    # magnitude better for log messages with format arguments that are expensive
    # to evaluate.
    rep, num = 3, 1000
    t = timeit.Timer( lambda: _log.log( _lognot,
                                        "%s", 
                                            " ".join( list( str( i ) for i in range( 100 )))))
    t1ms = 1000 * min( t.repeat( rep, num )) / num

    t = timeit.Timer( lambda: _log.log( _lognot, automata.lazystr( lambda: \
                                        "%s" % (
                    			    " ".join( list( str( i ) for i in range( 100 )))))))
    t2ms = 1000 * min( t.repeat( rep, num )) / num
    print("expensive: %.3f ms/loop avg; %s better" % ( t2ms, t1ms / t2ms ))
    assert t1ms / t2ms > 10.0

    # And ensure it is pretty good, even compared to the best case with minimal
    # operations on the arguments, but with lazily formatted log strings; quite
    # simple args requiring only a tiny bit of processing you'd typically see in
    # even the simplest log (str/repr of objects)
    a 				=     object()
    t = timeit.Timer( lambda: _log.log( _lognot,
                                        "%s: %r %d %d %d %d %d", 
                                            str( a ), repr( a ), 1, 2, 3, 4, 5 ))
    t3ms = 1000 * min( t.repeat( rep, num )) / num
    t = timeit.Timer( lambda: _log.log( _lognot, automata.lazystr( lambda: \
                                        "%s: %r %d %d %d %d %d" % (
                    			    str( a ), repr( a ), 1, 2, 3, 4, 5 ))))
    t4ms = 1000 * min( t.repeat( rep, num )) / num
    print("minimal: %.3f ms/loop avg; %s better" % ( t4ms, t3ms / t4ms ))
    assert t3ms / t4ms > 1.0

    # Only with no argument processing overhead at all is the overhead of the
    # lazy evaluation structure less performant than raw logging:
    a 				=     object()
    t = timeit.Timer( lambda: _log.log( _lognot, 
                                        "%s: %r %d %d %d %d %d",
                                            a, a, 1, 2, 3, 4, 5 ))
    t5ms = 1000 * min( t.repeat( rep, num )) / num
    t = timeit.Timer( lambda: _log.log( _lognot, automata.lazystr( lambda: \
                                        "%s: %r %d %d %d %d %d" % (
                    			    a, a, 1, 2, 3, 4, 5 ))))
    t6ms = 1000 * min( t.repeat( rep, num )) / num
    print("simplest: %.3f ms/loop avg; %s better" % ( t6ms, t5ms / t6ms ))
    assert t5ms / t6ms > .5


def test_iterators():
    i				= automata.chaining()
    j				= automata.chainable( i )
    k				= automata.chainable( 'abc' )
    assert i is j
    try:
        i.next()
        assert False, "stream with no iterable should raise StopIteration"
    except StopIteration:
        pass
    assert k is not j
    assert isinstance( k, automata.chaining )

    assert automata.peekable( i ) is i
    p				= automata.peekable()
    assert automata.peekable( p ) is p
    assert automata.chainable( p ) is not p

    i.chain('abc')
    i.chain('')
    i.chain( '123' )
    assert list( i ) == ['a','b','c','1','2','3']

    i.chain( 'y' )
    i.push( 'x' )
    assert list( i ) == ['x','y']

    i.chain( None )
    try:
        i.next()
        assert False, "Expected TypeError to be raised"
    except TypeError:
        pass
    except Exception as e:
        assert False, "Expected TypeError, not %r" % ( e )


def test_dfa():

    # Simple DFA with states consuming no input.  A NULL (None) state transition
    # doesn't require input for state change.  The Default (True) transition
    # requires input to make the transition, but none of these states consume
    # it, so it'll be left over at the end.
    a 				=     automata.state( "Initial" )
    a[None]			= b = automata.state( "Middle" )
    b[True]			= c = automata.state( "Terminal", terminal=True )

    source			= automata.chainable()
    i				= a.transition( source=source )
    m,s				= i.next()
    assert m is None
    assert s is not None and s.name == "Middle"
    try:
        i.next()
        assert False, "Expected no more non-transition events"
    except StopIteration:
        pass

    machine			= automata.dfa( initial=a )

    _log.info( "DFA:" )
    for initial in machine.initial.nodes():
        for inp,target in initial.edges():
            _log.info( "           %-15.15s <- %-10.10r -> %s" % ( initial, inp, target ))

    # Running with no input will yield the initial state, with None input; since
    # it is a NULL state (no input processed), it will simply attempt to
    # transition.  This will require the next input from source, which is empty,
    # so it will return input,state=(None, None) indicating a non-terminal state
    # and no input left.  This gives the caller an opportunity to reload input
    # and try again.
    _log.info( "States; No input" )
    source			= automata.chainable()
    sequence			= machine.run( source=source )
    for num in xrange( 10 ):
        try:
            mch,sta		= sequence.next()
        except StopIteration:
            sequence		= None
            break
        inp			= source.peek()
        _log.info( "%10.10s.%-15.15s <- %r" % ( mch, sta, inp ))
        if num == 0: assert inp is None; assert sta.name == "Initial"
        if num == 1: assert inp is None; assert sta.name == "Middle"
        if num == 2: assert inp is None; assert sta is None	# And no more no-input transitions
    assert num == 9
    # since the iterator did not stop cleanly (after processing a state's input,
    # and then trying to determine the next state), it'll continue indefinitely
    assert sta is None
    assert sequence is not None

    # Try with some input loaded into source stream, using the same generator
    # sequence.  Only the first element is gotten, and is reused for every NULL
    # state transition, and is left over at the end.  We'll be continuing the
    # last sequence, so we'll immediately transition.
    _log.info( "States; 'abc' input" )
    assert source.peek() is None
    source.chain( 'abc' )
    assert source.peek() == 'a'
    for num in xrange( 10 ):
        try:
            mch,sta		= sequence.next()
        except StopIteration:
            break
        inp			= source.peek()
        _log.info( "%10.10s.%-15.15s <- %r", mch, sta, inp )
        if num == 0: assert inp == 'a'; assert sta.name == "Terminal"
    assert num == 1
    assert inp == 'a'
    assert sta.name == "Terminal"


def test_struct():
    a				=     automata.state_input( "First" )
    a[True]			= b = automata.state_input( "Second" )
    b[True]			= c = automata.state_input( "Third" )
    c[True]			= d = automata.state_input( "Fourth" )
    d[None] 			= e = automata.state_struct( 
                                          "int32", format="<i", offset=4, terminal=True )
    machine			= automata.dfa( initial=a )
    material			= '\x01\x02\x03\x80\x99'
    segment			= 3
    source			= automata.chainable()
    _log.info( "States; %r input, by %d", material, segment )
    inp				= None
    sequence			= machine.run( source=source )
    for num in xrange( 100 ):
        try:
            mch,sta		= sequence.next()
            inp			= source.peek()
        except StopIteration:
            inp			= source.peek()
            _log.info( "%10.10s.%-15.15s <- %-10.10r test done", mch, sta, inp )
            break
        _log.info( "%10.10s.%-15.15s <- %-10.10r test rcvd", mch, sta, inp )
        if sta is None:
            _log.info( "%10.10s.%-15.15s <- %-10.10r test no next state", mch, sta, inp )
        if inp is None:
            if not material:
                _log.info( "%10.10s.%-15.15s <- %-10.10r test source finished", mch, sta, inp )
            # Will load consecutive empty iterables; chainable must handle
            source.chain( material[:segment] )
            material		= material[segment:]
            inp			= source.peek()
            _log.info( "%10.10s.%-15.15s <- %-10.10r test chain", mch, sta, inp )

        if num == 0: assert inp == '\x01'; assert sta.name == "First"
        if num == 1: assert inp == '\x02'; assert sta.name == "Second"
        if num == 2: assert inp == '\x03'; assert sta.name == "Third"
        if num == 3: assert inp == '\x80'; assert sta is None
        if num == 4: assert inp == '\x80'; assert sta.name == "Fourth"
        if num == 5: assert inp == '\x99'; assert sta.name == "int32"
        if num == 6: assert inp == '\x99'; assert sta.name == "int32"
    assert inp == '\x99'
    assert num == 6
    assert sta.name == "int32"
    assert machine.value == -2147286527

def test_fsm():
    import greenery
    regex			= greenery.parse( "a*b.*x" )
    machine			= automata.fsm( name="test1", initial=regex )

    source			= automata.chainable( 'aaaab1230xoxx' )
    sequence			= machine.run( source=source )
    for num in xrange( 100 ):
        try:
            mch,sta		= sequence.next()
            inp			= source.peek()
        except StopIteration:
            inp			= source.peek()
            _log.info( "%10.10s.%-15.15s <- %-10.10r test done", mch, sta, inp )
            break
        _log.info( "%10.10s.%-15.15s <- %-10.10r test rcvd", mch, sta, inp )
        if sta is None:
            _log.info( "%10.10s.%-15.15s <- %-10.10r test no next state", mch, sta, inp )
        if inp is None:
            _log.info( "%10.10s.%-15.15s <- %-10.10r test source finished", mch, sta, inp )

        if num == 0: assert inp == 'a'; assert sta.name == "0"
        if num == 1: assert inp == 'a'; assert sta.name == "0"
        if num == 2: assert inp == 'a'; assert sta.name == "0"
        if num == 3: assert inp == 'a'; assert sta.name == "0"
        if num == 4: assert inp == 'b'; assert sta.name == "2"
        if num == 5: assert inp == '1'; assert sta.name == "2"
        if num == 6: assert inp == '2'; assert sta.name == "2"
        if num == 7: assert inp == '3'; assert sta.name == "2"
        if num == 8: assert inp == '0'; assert sta.name == "2"
        if num == 9: assert inp == 'x'; assert sta.name == "3"
        if num ==10: assert inp == 'o'; assert sta.name == "2" # Trans. from term. to non-term. state!
        if num ==11: assert inp == 'x'; assert sta.name == "3"
        if num ==12: assert inp == 'x'; assert sta.name == "3"
        if num ==13: assert inp ==None; assert sta is None
    assert inp is None
    assert num == 13
    assert sta.name == '3'
