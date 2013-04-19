# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import print_function

import collections
import logging
import os
import sys
import timeit

# Allow relative imports when executing within package directory, for running tests
sys.path.insert( 0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cpppo
from . import misc

logging.basicConfig( **cpppo.log_cfg )
log				= logging.getLogger()
log_not				= log.level-1

def test_logging():
    # Test lazy log message evaluation, ensuring it is at least an order of
    # magnitude better for log messages with format arguments that are expensive
    # to evaluate.
    rep, num = 3, 1000
    t = timeit.Timer( lambda: log.log( log_not,
                                        "%s", 
                                            " ".join( list( str( i ) for i in range( 100 )))))
    t1ms = 1000 * min( t.repeat( rep, num )) / num

    t = timeit.Timer( lambda: log.log( log_not, cpppo.lazystr( lambda: \
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
    t = timeit.Timer( lambda: log.log( log_not,
                                        "%s: %r %d %d %d %d %d", 
                                            str( a ), repr( a ), 1, 2, 3, 4, 5 ))
    t3ms = 1000 * min( t.repeat( rep, num )) / num
    t = timeit.Timer( lambda: log.log( log_not, cpppo.lazystr( lambda: \
                                        "%s: %r %d %d %d %d %d" % (
                    			    str( a ), repr( a ), 1, 2, 3, 4, 5 ))))
    t4ms = 1000 * min( t.repeat( rep, num )) / num
    print("minimal: %.3f ms/loop avg; %s better" % ( t4ms, t3ms / t4ms ))
    assert t3ms / t4ms > 1.0

    # Only with no argument processing overhead at all is the overhead of the
    # lazy evaluation structure less performant than raw logging:
    a 				=     object()
    t = timeit.Timer( lambda: log.log( log_not, 
                                        "%s: %r %d %d %d %d %d",
                                            a, a, 1, 2, 3, 4, 5 ))
    t5ms = 1000 * min( t.repeat( rep, num )) / num
    t = timeit.Timer( lambda: log.log( log_not, cpppo.lazystr( lambda: \
                                        "%s: %r %d %d %d %d %d" % (
                    			    a, a, 1, 2, 3, 4, 5 ))))
    t6ms = 1000 * min( t.repeat( rep, num )) / num
    print("simplest: %.3f ms/loop avg; %s better" % ( t6ms, t5ms / t6ms ))
    assert t5ms / t6ms > .5


def test_iterators():
    i				= cpppo.chaining()
    j				= cpppo.chainable( i )
    k				= cpppo.chainable( 'abc' )
    assert i is j
    try:
        next( i )
        assert False, "stream with no iterable should raise StopIteration"
    except StopIteration:
        pass
    assert k is not j
    assert isinstance( k, cpppo.chaining )

    assert cpppo.peekable( i ) is i
    p				= cpppo.peekable()
    assert cpppo.peekable( p ) is p
    assert cpppo.chainable( p ) is not p

    i.chain('abc')
    i.chain('')
    i.chain( '123' )
    assert list( i ) == ['a','b','c','1','2','3']

    i.chain( 'y' )
    i.push( 'x' )
    assert list( i ) == ['x','y']

    i.chain( None )
    try:
        next( i )
        assert False, "Expected TypeError to be raised"
    except TypeError:
        pass
    except Exception as e:
        assert False, "Expected TypeError, not %r" % ( e )


def test_state():
    # A state is expected to process its input (perhaps nothing, if its a
    # no-input state), and then use the next input symbol to transition to
    # another state.  Each state has a context into a data artifact, into which
    # it will collect its results.
    pass

def test_dfa():

    # Simple DFA with states consuming no input.  A NULL (None) state transition
    # doesn't require input for state change.  The Default (True) transition
    # requires input to make the transition, but none of these states consume
    # it, so it'll be left over at the end.
    a 				=     cpppo.state( "Initial" )
    a[None]			= b = cpppo.state( "Middle" )
    b[True]			= c = cpppo.state( "Terminal", terminal=True )

    source			= cpppo.chainable()
    i				= a.run( source=source )
    m,s				= next( i )
    assert m is None
    assert s is not None and s.name == "Middle"
    try:
        next( i )
        assert False, "Expected no more non-transition events"
    except StopIteration:
        pass

    machine			= cpppo.dfa( initial=a )

    log.info( "DFA:" )
    for initial in machine.initial.nodes():
        for inp,target in initial.edges():
            log.info( "%s <- %-10.10r -> %s" % ( misc.centeraxis( initial, 25, clip=True ), inp, target ))

    # Running with no input will yield the initial state, with None input; since
    # it is a NULL state (no input processed), it will simply attempt to
    # transition.  This will require the next input from source, which is empty,
    # so it will return input,state=(None, None) indicating a non-terminal state
    # and no input left.  This gives the caller an opportunity to reload input
    # and try again.
    log.info( "States; No input" )
    source			= cpppo.chainable()
    sequence			= machine.run( source=source )
    for num in range( 10 ):
        try:
            mch,sta		= next( sequence )
        except StopIteration:
            sequence		= None
            break
        inp			= source.peek()
        log.info( "%s <- %r" % ( misc.centeraxis( mch, 25, clip=True ), inp ))
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
    log.info( "States; 'abc' input" )
    assert source.peek() is None
    source.chain( b'abc' )
    assert source.peek() == next(iter(b'a')) # python2: str, python3: int
    for num in range( 10 ):
        try:
            mch,sta		= next( sequence )
        except StopIteration:
            break
        inp			= source.peek()
        log.info( "%s <- %r", misc.centeraxis( mch, 25, clip=True ), inp )
        if num == 0: assert inp == next(iter(b'a')); assert sta.name == "Terminal"
    assert num == 1
    assert inp == next(iter(b'a'))
    assert sta.name == "Terminal"


def test_struct():
    dtp				= cpppo.type_bytes_array_symbol
    abt				= cpppo.type_bytes_iter
    ctx				= 'val'
    a				=     cpppo.state_input( "First",  alphabet=abt, typecode=dtp, context=ctx )
    a[True]			= b = cpppo.state_input( "Second", alphabet=abt, typecode=dtp, context=ctx )
    b[True]			= c = cpppo.state_input( "Third",  alphabet=abt, typecode=dtp, context=ctx )
    c[True]			= d = cpppo.state_input( "Fourth", alphabet=abt, typecode=dtp, context=ctx )
    d[None] 			= e = cpppo.state_struct( "int32", context=ctx,
                                                          format="<i", offset=4,
                                                          terminal=True )
    machine			= cpppo.dfa( initial=a )
    material			= b'\x01\x02\x03\x80\x99'
    segment			= 3
    source			= cpppo.chainable()
    log.info( "States; %r input, by %d", material, segment )
    inp				= None
    data			= cpppo.dotdict()
    path			= "struct"
    sequence			= machine.run( source=source, path=path, data=data )
    for num in range( 10 ):
        try:
            mch,sta		= next( sequence )
            inp			= source.peek()
        except StopIteration:
            inp			= source.peek()
            log.info( "%s <- %-10.10r test done", misc.centeraxis( mch, 25, clip=True ), inp )
            break
        log.info( "%s <- %-10.10r test rcvd", misc.centeraxis( mch, 25, clip=True ), inp )
        if sta is None:
            log.info( "%s <- %-10.10r test no next state", misc.centeraxis( mch, 25, clip=True ), inp )
        if inp is None:
            if not material:
                log.info( "%s <- %-10.10r test source finished", misc.centeraxis( mch, 25, clip=True ), inp )
            # Will load consecutive empty iterables; chainable must handle
            source.chain( material[:segment] )
            material		= material[segment:]
            inp			= source.peek()
            log.info( "%s <- %-10.10r test chain", misc.centeraxis( mch, 25, clip=True ), inp )

        if num == 0: assert inp == next(iter(b'\x01')); assert sta.name == "First"
        if num == 1: assert inp == next(iter(b'\x02')); assert sta.name == "Second"
        if num == 2: assert inp == next(iter(b'\x03')); assert sta.name == "Third"
        if num == 3: assert inp == next(iter(b'\x80')); assert sta is None
        if num == 4: assert inp == next(iter(b'\x80')); assert sta.name == "Fourth"
        if num == 5: assert inp == next(iter(b'\x99')); assert sta.name == "int32"
        if num == 6: assert inp == next(iter(b'\x99')); assert sta.name == "int32"
    assert inp == next(iter(b'\x99'))
    assert num == 6
    assert sta.name == "int32"
    assert data.struct.val == -2147286527

def test_fsm():
    regex			= 'a*b.*x'
    machine			= cpppo.fsm( name="test1", initial=regex, alphabet=str )

    source			= cpppo.chainable( 'aaaab1230xoxx' )
    sequence			= machine.run( source=source )
    for num in range( 20 ):
        try:
            mch,sta		= next( sequence )
            inp			= source.peek()
        except StopIteration:
            inp			= source.peek()
            log.info( "%s <- %-10.10r test done", misc.centeraxis( mch, 25, clip=True ), inp )
            break
        log.info( "%s <- %-10.10r test rcvd", misc.centeraxis( mch, 25, clip=True ), inp )
        if sta is None:
            log.info( "%s <- %-10.10r test no next state", misc.centeraxis( mch, 25, clip=True ), inp )
        if inp is None:
            log.info( "%s <- %-10.10r test source finished", misc.centeraxis( mch, 25, clip=True ), inp )

        if num == 0: assert inp == next(iter('a')); assert sta.name == "0"
        if num == 1: assert inp == next(iter('a')); assert sta.name == "0"
        if num == 2: assert inp == next(iter('a')); assert sta.name == "0"
        if num == 3: assert inp == next(iter('a')); assert sta.name == "0"
        if num == 4: assert inp == next(iter('b')); assert sta.name == "2"
        if num == 5: assert inp == next(iter('1')); assert sta.name == "2"
        if num == 6: assert inp == next(iter('2')); assert sta.name == "2"
        if num == 7: assert inp == next(iter('3')); assert sta.name == "2"
        if num == 8: assert inp == next(iter('0')); assert sta.name == "2"
        if num == 9: assert inp == next(iter('x')); assert sta.name == "3"
        if num ==10: assert inp == next(iter('o')); assert sta.name == "2" # Trans. from term. to non-term. state!))
        if num ==11: assert inp == next(iter('x')); assert sta.name == "3"
        if num ==12: assert inp == next(iter('x')); assert sta.name == "3"
        if num ==13: assert inp ==None; assert sta is None
    assert inp is None
    assert num == 13
    assert sta.name == '3'


import binascii
import codecs
def to_hex( data, nbytes ):
    "Format bytes 'data' as a sequence of nbytes long values separated by spaces."
    chars_per_item		= nbytes * 2
    hex_version			= binascii.hexlify( data )
    def chunkify():
        for start in range( 0, len( hex_version ), chars_per_item ):
            yield hex_version[start:start + chars_per_item]
    return b' '.join( chunkify() )


def test_codecs():
    # In Python3, the greenery FSM is able to handle the Unicode str type; under
    # Python2, it can sanely only handle the non-Unicode str type.
    if sys.version_info.major < 3:
        return

    # Test parsing of greenery.fsm/lego regexes specified in Unicode.  Then,
    # generate corresponding cpppo state machines that accept Unicode input
    # symbols, and byte input symbols.

    texts 			= [
        u'pi: π',
        u'abcdé\u4500123',
        u'This contains π,π and more πs',
        u'a 480Ω resistor',
        ]
    '''
    for text in texts:
        encoded = text.encode('utf-8')
        decoded = encoded.decode('utf-8')
        
        print( 'Original : "%s"' % text, repr( text ))
        print( 'Encoded  : ', to_hex( encoded, 1 ), type( encoded ))
        print( 'Decoded  : "%s"' % decoded, repr( decoded ), type( decoded ))
    '''

    for text in texts:
        # First, convert the unicode fsm to a state machine in unicode symbols.
        pies			= cpppo.fsm( name="pies", initial=".*π.*" )
        
        source			= cpppo.chainable( text )
        data			= cpppo.dotdict()
        for mch, sta in pies.run( source=source, data=data, greedy=True ):
            if sta is None:
                log.info( "%sr done", misc.centeraxis( mch, 25, clip=True ))
                break
            log.info( "%s reports %s", misc.centeraxis( mch, 25, clip=True ), sta )
        log.info( "%s ends in %s: %s: %r", misc.centeraxis( mch, 25, clip=True ), sta,
                  "string accepted" if sta and sta.terminal else "string rejected", data )

        # Each of these are greedy, and so run 'til the end of input (next state
        # is None); they collect the full input string.
        assert ( sta is not None and sta.terminal ) == ( u"π" in text )
        assert data._.tounicode() == text

    for text in texts:
        # Then convert the unicode fsm to a state machine in bytes symbols.
        # Our encoder generates 1 or more bytes for each unicode symbol.

        pies			= cpppo.fsm( name="pies", initial=".*π.*", 
                                             fsm_alphabet=int,
                                             fsm_typecode='B',
                                             fsm_encoder=lambda s: ( b for b in s.encode( 'utf-8' )))
        
        source			= cpppo.chainable( text.encode( 'utf-8' ))
        data			= cpppo.dotdict()

        for mch, sta in pies.run( source=source, data=data, greedy=True ):
            if sta is None:
                log.info( "%sr done", misc.centeraxis( mch, 25, clip=True ))
                break
            log.info( "%s reports %s", misc.centeraxis( mch, 25, clip=True ), sta )
        log.info( "%s ends in %s: %s: %r", misc.centeraxis( mch, 25, clip=True ), sta,
                  "string accepted" if sta and sta.terminal else "string rejected", data )

        assert ( sta is not None and sta.terminal ) == ( u"π" in text )
        assert data._.tobytes().decode('utf-8') == text
