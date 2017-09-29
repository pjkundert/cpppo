# -*- coding: utf-8 -*-

# Since 3.2 doesn't accept u'...' strings, we cannot test mixed string/unicode literals in the same
# file, without explicitly "casting" to str in 2.x with str('...').  Without from __future__ import
# unicode_literals, we cannot have any literals at all with unicode characters under 2.x, while
# maintaining 3.2 compatibilty.  This is unfortunate.

from __future__ import absolute_import, print_function, division, unicode_literals
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass


import binascii
import logging
import pytest
import sys
import timeit

import cpppo

logging.basicConfig( **cpppo.log_cfg )
log				= logging.getLogger()
log_not				= 0
#log.setLevel( logging.INFO )
#log.setLevel( logging.DEBUG )

def test_logging():
    # Test lazy log message evaluation, ensuring it is at least an order of magnitude better for log
    # messages with format arguments that are expensive to evaluate.  Should be at least an order of
    # magnitude (10 x) faster, but check for at least 8 x.
    rep, num = 3, 1000
    t = timeit.Timer( lambda: log.log( log_not,
                                        "%s", 
                                            " ".join( list( str( i ) for i in range( 100 )))))
    t1ms = 1000 * min( t.repeat( rep, num )) / num

    t = timeit.Timer( lambda: log.log( log_not, cpppo.lazystr( lambda: \
                                        "%s" % (
                    			    " ".join( list( str( i ) for i in range( 100 )))))))
    t2ms = 1000 * min( t.repeat( rep, num )) / num
    log.normal( "expensive: %.3f ms/loop avg; %s better", t2ms, t1ms / t2ms )
    assert round( t1ms / t2ms ) >= 8.0, \
        "Didn't achieve expected speedup %s vs. %s: %s x is less than 8.0" % (
            t2ms, t1ms, round( t1ms / t2ms ))

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
    log.normal( "minimal: %.3f ms/loop avg; %s better", t4ms, t3ms / t4ms )
    #assert t3ms / t4ms > 1.0 # timing too unreliable to assert

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
    log.normal( "simplest: %.3f ms/loop avg; %s better", t6ms, t5ms / t6ms )
    #assert t5ms / t6ms > .5 # timing too unreliable to assert


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
    p				= cpppo.peekable( '123' )
    assert cpppo.peekable( p ) is p
    assert cpppo.chainable( p ) is not p
    assert list( p ) == ['1', '2', '3']
    assert p.sent == 3
    p.push('x')
    assert p.sent == 2
    assert list( p ) == ['x']
    assert list( p ) == []


    i.chain('abc')
    i.chain('')
    i.chain( '123' )
    assert list( i ) == ['a','b','c','1','2','3']
    assert i.sent == 6

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


    r				= cpppo.rememberable( '123' )
    assert next( r ) == '1'
    assert r.memory == [ '1' ]
    try:
        r.push( 'x' )
        assert False, "Should have rejected push of inconsistent symbol"
    except AssertionError:
        pass
    assert r.sent == 1
    r.push( '1' )
    assert r.sent == 0
    assert r.memory == []
    assert list( r ) == r.memory == [ '1', '2','3' ]


def test_readme():
    """The basic examples in the README"""

    # Basic DFA that accepts ab+
    E				= cpppo.state( "E" )
    A				= cpppo.state_input( "A" )
    B				= cpppo.state_input( "B", terminal=True )
    E['a']			= A
    A['b']			= B
    B['b']			= B

    data			= cpppo.dotdict()
    source			= cpppo.peekable( str( 'abbbb,ab' ))
    with cpppo.dfa( initial=E ) as abplus:
        for i,(m,s) in enumerate( abplus.run( source=source, path="ab+", data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 5
    assert source.peek() == str(',')
    
    # Composite state machine accepting ab+, ignoring ,[ ]* separators
    CSV				= cpppo.dfa( "CSV", initial=E, terminal=True )
    SEP				= cpppo.state_drop( "SEP" )

    CSV[',']			= SEP
    SEP[' ']			= SEP
    SEP[None]			= CSV

    source			= cpppo.peekable( str( 'abbbb, ab' ))
    with cpppo.dfa( initial=CSV ) as r2:
        for i,(m,s) in enumerate( r2.run( source=source, path="readme_CSV", data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 14
    assert source.peek() is None
    

def test_state():
    """A state is expected to process its input (perhaps nothing, if its a no-input state), and then use
    the next input symbol to transition to another state.  Each state has a context into a data
    artifact, into which it will collect its results.

    We must ensure that all state transitions are configured in the target alphabet; if an encoder
    is supplied, then all input symbols and all transition symbols will be encoded using it.  In
    this test, all string literals are Unicode (in both Python 2 and 3), so we use a unicode encoder
    to convert them to symbols."""

    unicodekwds			= {
        'alphabet':	unicode if sys.version_info[0] < 3 else str,
        'encoder':	cpppo.type_unicode_encoder,
    }
    s1				= cpppo.state(
        'one', **unicodekwds )
    s2				= cpppo.state_drop(
        'two', **unicodekwds )

    s1['a']			= s2
    assert s1['a'] is s2

    source			= cpppo.peeking( 'abc' )

    # We can run state instances with/without acquisition
    g				= s1.run( source=source )
    assert next( g ) == (None, s2)
    assert source.peek() == 'a'
    with pytest.raises(StopIteration):
        next( g )
    with s1:
        g			= s1.run( source=source )
        assert source.peek() == 'a'
        assert next( g ) == (None, s2)
        assert source.peek() == 'a'
        try:
            next( g )
            assert False, "Should have terminated"
        except StopIteration:
            pass
        assert source.peek() == 'a'

    
    # A state machine accepting a sequence of unicode a's
    a_s				= cpppo.state( 		"a_s", **unicodekwds )
    an_a			= cpppo.state_input(	"a",   terminal=True,
                                                        typecode=cpppo.type_unicode_array_symbol,
                                                        **unicodekwds )
    a_s['a']			= an_a
    an_a['a']			= an_a

    source			= cpppo.peeking( 'aaaa' )
    data			= cpppo.dotdict()

    with cpppo.dfa( initial=a_s ) as aplus:
        for i,(m,s) in enumerate( aplus.run( source=source )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 5
        assert source.peek() is None
        assert len( data ) == 0

    # Accepting a's separated by comma and space/pi (for kicks).  When the lower level a's machine
    # doesn't recognize the symbol, then the higher level machine will recognize and discard
    sep				= cpppo.state_drop(	"sep", **unicodekwds )
    csv				= cpppo.dfa( "csv", initial=a_s , terminal=True, **unicodekwds )
    csv[',']			= sep
    sep[' ']			= sep
    sep['π']			= sep
    sep[None]			= csv
    
    source			= cpppo.peeking( 'aaaa, a,π a' )
    data			= cpppo.dotdict()

    with cpppo.dfa( initial=csv ) as csvaplus:
        for i,(m,s) in enumerate( csvaplus.run( source=source, path="csv", data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                i, s, source.sent, source.peek(), data )
        assert i == 18
        assert source.peek() is None
    assert data.csv.input.tounicode() == 'aaaaaa'

def test_dfa():
    # Simple DFA with states consuming no input.  A NULL (None) state transition
    # doesn't require input for state change.  The Default (True) transition
    # requires input to make the transition, but none of these states consume
    # it, so it'll be left over at the end.
    a 				= cpppo.state( "Initial" )
    a[None] = b			= cpppo.state( "Middle" )
    b[True]			= cpppo.state( "Terminal", terminal=True )

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

    with machine:
        log.info( "DFA:" )
        for initial in machine.initial.nodes():
            for inp,target in initial.edges():
                log.info( "%s <- %-10.10r -> %s" % ( cpppo.centeraxis( initial, 25, clip=True ),
                                                     inp, target ))

        # Running with no input will yield the initial state, with None input; since it is a NULL
        # state (no input processed), it will simply attempt to transition.  This will require the
        # next input from source, which is empty, so it will return input,state=(None, None)
        # indicating a non-terminal state and no input left.  This gives the caller an opportunity
        # to reload input and try again.  If a loop is detected (same state and input conditions
        # seen repeatedly), the DFA will terminate; if not in a terminal state, an exception will be
        # raised.
        log.info( "States; No input" )
        source			= cpppo.chainable()
        sequence		= machine.run( source=source )
        for num in range( 10 ):
            try:
                mch,sta		= next( sequence )
            except StopIteration:
                sequence	= None
                break
            except cpppo.NonTerminal as e:
                assert "non-terminal state" in str( e )
                break

            inp			= source.peek()
            log.info( "%s <- %r" % ( cpppo.centeraxis( mch, 25, clip=True ), inp ))
            if num == 0: assert inp is None; assert sta.name == "Initial"
            if num == 1: assert inp is None; assert sta.name == "Middle"
            if num == 2: assert inp is None; assert sta is None	# And no more no-input transitions
            assert num < 3 # If we get here, we didn't detect loop
        assert num == 3

        # since the iterator did not stop cleanly (after processing a state's input,
        # and then trying to determine the next state), it'll continue indefinitely
        assert sta is None
        assert sequence is not None
    
        # Try with some input loaded into source stream, using an identical generator sequence.
        # Only the first element is gotten, and is reused for every NULL state transition, and is
        # left over at the end.
        log.info( "States; 'abc' input" )
        assert source.peek() is None
        source.chain( b'abc' )
        assert source.peek() == b'a'[0] # python2: str, python3: int
        sequence		= machine.run( source=source )
        for num in range( 10 ):
            try:
                mch,sta		= next( sequence )
            except StopIteration:
                break
            inp			= source.peek()
            log.info( "%s <- %r", cpppo.centeraxis( mch, 25, clip=True ), inp )
            if num == 0: assert inp == b'a'[0]; assert sta.name == "Initial"
            if num == 1: assert inp == b'a'[0]; assert sta.name == "Middle"
            if num == 2: assert inp == b'a'[0]; assert sta.name == "Terminal"
            assert num < 3
        assert num == 3
        assert inp == b'a'[0]
        assert sta.name == "Terminal"


def test_struct():
    dtp				= cpppo.type_bytes_array_symbol
    abt				= cpppo.type_bytes_iter
    ctx				= 'val'
    a				= cpppo.state_input( "First",  alphabet=abt, typecode=dtp, context=ctx )
    a[True] = b 		= cpppo.state_input( "Second", alphabet=abt, typecode=dtp, context=ctx )
    b[True] = c 		= cpppo.state_input( "Third",  alphabet=abt, typecode=dtp, context=ctx )
    c[True] = d			= cpppo.state_input( "Fourth", alphabet=abt, typecode=dtp, context=ctx )
    d[None] 			= cpppo.state_struct( "int32", context=ctx,
                                                      format=str("<i"),
                                                      terminal=True )
    machine			= cpppo.dfa( initial=a )
    with machine:
        material		= b'\x01\x02\x03\x80\x99'
        segment			= 3
        source			= cpppo.chainable()
        log.info( "States; %r input, by %d", material, segment )
        inp			= None
        data			= cpppo.dotdict()
        path			= "struct"
        sequence		= machine.run( source=source, path=path, data=data )
        for num in range( 10 ):
            try:
                mch,sta		= next( sequence )
                inp		= source.peek()
            except StopIteration:
                inp		= source.peek()
                log.info( "%s <- %-10.10r test done", cpppo.centeraxis( mch, 25, clip=True ), inp )
                break
            log.info( "%s <- %-10.10r test rcvd", cpppo.centeraxis( mch, 25, clip=True ), inp )
            if sta is None:
                log.info( "%s <- %-10.10r test no next state", cpppo.centeraxis( mch, 25, clip=True ), inp )
            if inp is None:
                if not material:
                    log.info( "%s <- %-10.10r test source finished", cpppo.centeraxis( mch, 25, clip=True ), inp )
                # Will load consecutive empty iterables; chainable must handle
                source.chain( material[:segment] )
                material		= material[segment:]
                inp			= source.peek()
                log.info( "%s <- %-10.10r test chain", cpppo.centeraxis( mch, 25, clip=True ), inp )
    
            if num == 0: assert inp == b'\x01'[0]; assert sta.name == "First"
            if num == 1: assert inp == b'\x02'[0]; assert sta.name == "Second"
            if num == 2: assert inp == b'\x03'[0]; assert sta.name == "Third"
            if num == 3: assert inp == b'\x80'[0]; assert sta is None
            if num == 4: assert inp == b'\x80'[0]; assert sta.name == "Fourth"
            if num == 5: assert inp == b'\x99'[0]; assert sta.name == "int32"
            if num == 6: assert inp == b'\x99'[0]; assert sta.name == "int32"
        assert inp == b'\x99'[0]
        assert num == 6
        assert sta.name == "int32"
        assert data.struct.val == -2147286527
    

def test_regex():
    # This forces plain strings in 2.x, unicode in 3.x (counteracts import unicode_literals above)
    regex			= str('a*b.*x')
    machine			= cpppo.regex( name=str('test1'), initial=regex )
    with machine:
        source			= cpppo.chainable( str('aaab1230xoxx') )
        sequence		= machine.run( source=source )
        for num in range( 20 ):
            try:
                mch,sta		= next( sequence )
                inp		= source.peek()
            except StopIteration:
                inp		= source.peek()
                log.info( "%s <- %-10.10r test done", cpppo.centeraxis( mch, 25, clip=True ), inp )
                break
            log.info( "%s <- %-10.10r test rcvd", cpppo.centeraxis( mch, 25, clip=True ), inp )
            if sta is None:
                log.info( "%s <- %-10.10r test no next state", cpppo.centeraxis( mch, 25, clip=True ), inp )
            if inp is None:
                log.info( "%s <- %-10.10r test source finished", cpppo.centeraxis( mch, 25, clip=True ), inp )
    
            # Initial state does *not* consume a source symbol
            if num == 0: assert inp == 'a'; assert sta.name == "0'"; assert source.sent == 0
            if num == 1: assert inp == 'a'; assert sta.name == "0";  assert source.sent == 0
            if num == 2: assert inp == 'a'; assert sta.name == "0";  assert source.sent == 1
            if num == 3: assert inp == 'a'; assert sta.name == "0";  assert source.sent == 2
            if num == 4: assert inp == 'b'; assert sta.name == "2"
            if num == 5: assert inp == '1'; assert sta.name == "2"
            if num == 6: assert inp == '2'; assert sta.name == "2"
            if num == 7: assert inp == '3'; assert sta.name == "2"
            if num == 8: assert inp == '0'; assert sta.name == "2"
            if num == 9: assert inp == 'x'; assert sta.name == "3"
            if num ==10: assert inp == 'o'; assert sta.name == "2" # Trans. from term. to non-term. state!))
            if num ==11: assert inp == 'x'; assert sta.name == "3"
            if num ==12: assert inp == 'x'; assert sta.name == "3"
            if num ==13: assert inp ==None; assert sta is None
            assert num < 14
        assert inp is None
        assert num == 14
        assert sta is None and machine.current.name == '3'

    regex			= str('.*')
    machine			= cpppo.regex( name=str('dot'), initial=regex, terminal=True )
    data			= cpppo.dotdict()
    with machine:
        source			= cpppo.chainable( str('aaab1230xoxx\0') )
        try:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
        except cpppo.NonTerminal:
            pass
        assert machine.terminal
        assert i == 14
        assert source.sent == 13
        if sys.version_info[0] < 3:
            assert data.input.input.tostring()  == 'aaab1230xoxx\x00'
        else:
            assert data.input.input.tounicode() == 'aaab1230xoxx\x00'

    regex			= str('[^xyz]*')
    machine			= cpppo.regex( name=str('not_xyz'), initial=regex )
    data			= cpppo.dotdict()
    with machine:
        source			= cpppo.chainable( str('aaab1230xoxx\0') )
        try:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
        except cpppo.NonTerminal:
            pass
        assert not machine.terminal
        assert i == 9
        assert source.sent == 8
        if sys.version_info[0] < 3:
            assert data.input.input.tostring()  == 'aaab1230'
        else:
            assert data.input.input.tounicode() == 'aaab1230'

    regex			= str('[^\x00]*')
    machine			= cpppo.regex( name=str('not_NUL'), initial=regex )
    data			= cpppo.dotdict()
    with machine:
        source			= cpppo.chainable( str('aaab1230xoxx\0') )
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 13
        assert source.sent == 12
        if sys.version_info[0] < 3:
            assert data.input.input.tostring()  == 'aaab1230xoxx'
        else:
            assert data.input.input.tounicode() == 'aaab1230xoxx'

def test_regex_demo():
    regex			= str( '(ab+)((,[ ]*)(ab+))*' )
    machine			= cpppo.regex( name=str( 'demo' ), initial=regex )
    data			= cpppo.dotdict()
    with machine:
        source			= cpppo.chainable( str( 'abbb, abb, ab' ))
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 14
        assert source.sent == 13

    regexstr, lego, machine, initial = cpppo.state_input.from_regex(
            regex, alphabet=cpppo.type_str_iter, encoder=None, 
            typecode=cpppo.type_str_array_symbol, context=None )
    assert str( lego ) == "ab+(, *ab+)*"
    assert str( machine ) == """\
  name final?   , None a b 
---------------------------
* 0    False  1 1 1    2 1 
  1    False  1 1 1    1 1 
  2    False  1 1 1    1 3 
  3    True   1 4 1    1 3 
  4    False  4 1 1    2 1 
"""

def to_hex( data, nbytes ):
    "Format bytes 'data' as a sequence of nbytes long values separated by spaces."
    chars_per_item		= nbytes * 2
    hex_version			= binascii.hexlify( data )
    def chunkify():
        for start in range( 0, len( hex_version ), chars_per_item ):
            yield hex_version[start:start + chars_per_item]
    return b' '.join( chunkify() )


def test_codecs():
    # In Python3, the greenery.fsm is able to handle the Unicode str type; under
    # Python2, it can sanely only handle the non-Unicode str type.
    if sys.version_info[0] < 3:
        return

    # Test parsing of greenery.fsm/lego regexes specified in Unicode.  Then,
    # generate corresponding cpppo state machines that accept Unicode input
    # symbols, and byte input symbols.  These tests will accept as much of the
    # input as matches the regular expression.


    texts 			= [
        'pi: π',
        'abcdé\u4500123',
        'This contains π,π and more πs',
        'a 480Ω resistor',
        ]
    tests			= [
        ('[^π]*(π[^π]*)+',	True),	# Optional non-π's, followed by at least one string of π and non-π's
        ('[^π]*[^π]',		False) 	# Any number of non-π, ending in a non-π
        ]

    for text in texts:
        for re,tr in tests:
            # First, convert the unicode regex to a state machine in unicode symbols.  Only if both
            # the dfa and its sub-state are "terminal", will it be terminal.
            with cpppo.regex(
                    name='pies',  context="pies", initial=re, terminal=True ) as pies:
                original		= text
                source			= cpppo.chainable( original )
                data			= cpppo.dotdict()
                try:
                    for mch, sta in pies.run( source=source, data=data ):
                        pass
                except cpppo.NonTerminal:
                    pass
                accepted		= pies.terminal and data.pies.input.tounicode() == original
                log.info( "%s ends w/ re %s: %s: %r", pies.name_centered(), re,
                          "string accepted" if accepted else "string rejected", data )
            
                # Each of these are greedy, and so run 'til the end of input (next state is None); they
                # collect the full input string, unless they run into a non-matching input.
                expected		= tr == ('π' in text )
                assert accepted == expected

    for text in texts:
        # Then convert the unicode regex to a state machine in bytes symbols.
        # Our encoder generates 1 or more bytes for each unicode symbol.
        for re,tr in tests:
            original		= text.encode( 'utf-8' ) # u'...' --> b'...'
            source		= cpppo.chainable( original )
            data		= cpppo.dotdict()

            with cpppo.regex(
                    name='pies', context="pies", initial=re, terminal=True,
                    regex_alphabet=int,
                    regex_typecode='B',
                    regex_encoder=lambda s: ( b for b in s.encode( 'utf-8' ))) as pies:
                try:
                    for mch, sta in pies.run( source=source, data=data ):
                        pass
                except cpppo.NonTerminal:
                    pass
                accepted		= pies.terminal and data.pies.input.tobytes() == original
                log.detail( "%s ends w/ re: %s: %s: %r", pies.name_centered(), re,
                          "string accepted" if accepted else "string rejected", data )
                expected		= tr == ('π' in text )
                assert accepted == expected
                assert original.startswith( data.pies.input.tobytes() )


def test_decide():
    """Allow state transition decisions based on collected context other than just
    the next source symbol.

    """
    e				= cpppo.state( "enter" )
    e['a'] = a			= cpppo.state_input( "a", context='a' )
    a[' '] = s1			= cpppo.state_drop( "s1" )
    s1[' '] = s1
    s1[None] = i1		= cpppo.integer( "i1", context='i1' )
    
    i1[' '] = s2		= cpppo.state_drop( "s2" )
    s2[' '] = s2
    s2[None] = i2		= cpppo.integer( "i2", context='i2' )
    less			= cpppo.state( "less", terminal=True )
    greater			= cpppo.state( "greater", terminal=True )
    equal			= cpppo.state( "equal", terminal=True )
    i2[None] 			= cpppo.decide(
        "isless", less, predicate=lambda machine,source,path,data: data.i1 < data.i2 )
    i2[None] 			= cpppo.decide(
        "isgreater", greater, predicate=lambda machine,source,path,data: data.i1 > data.i2)
    i2[None]			= equal


    source			= cpppo.peekable( str('a 1 2') )
    data			= cpppo.dotdict()
    with cpppo.dfa( "comparo", initial=e ) as comparo:
        for i,(m,s) in enumerate( comparo.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 12
        assert s is less
            
    source			= cpppo.peekable( str('a 33 33') )
    data			= cpppo.dotdict()
    with cpppo.dfa( "comparo", initial=e ) as comparo:
        for i,(m,s) in enumerate( comparo.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 14
        assert s is equal

def test_limit():
    # Force a limit on input symbols.  If we only accept only even b's, we'll
    # fail if we force a stoppage at a+b*9
    source			= cpppo.peekable( str( 'a'+'b'*100 ))
    data			= cpppo.dotdict()
    try:
        with cpppo.regex( initial=str( 'a(bb)*' ), context='even_b', limit=10 ) as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
    except cpppo.NonTerminal:
        assert i == 10
        assert source.sent == 10
    else:
        assert False, "Should have failed with a cpppo.NonTerminal exception"


    # But odd b's OK
    for limit in [
            10, 
            '..somewhere.ten',
            lambda **kwds: 10, 
            lambda path=None, data=None, **kwds: data[path+'..somewhere.ten'] ]:
        source			= cpppo.peekable( str( 'a'+'b'*100 ))
        data			= cpppo.dotdict()
        data['somewhere.ten']	= 10
        with cpppo.regex( initial=str( 'ab(bb)*' ), context='odd_b', limit=limit ) as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
            assert i == 10
            assert source.sent == 10
            assert ( data.odd_b.input.tostring()
                     if sys.version_info[0] < 3
                     else data.odd_b.input.tounicode() ) == str( 'a'+'b'*9 )
        
def test_decode():
    # Test decode of regexes over bytes data.  Operates in raw bytes symbols., works in Python 2/3.
    source			= cpppo.peekable( 'π'.encode( 'utf-8' ))
    data			= cpppo.dotdict()
    with cpppo.string_bytes( 'pi', initial='.*', greedy=True, context='pi', decode='utf-8' ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 3
        assert source.sent == 2
        assert data.pi == 'π'
    
    if sys.version_info[0] < 3:
        # Test regexes over plain string data (no decode required).  Force non-unicode (counteracts
        # import unicode_literals above).  We can't use greenery.lego regexes on unicode data in
        # Python 2...
        source			= cpppo.peekable( str( 'pi' ))
        data			= cpppo.dotdict()
        with cpppo.string( 'pi', initial='.*', greedy=True, context='pi' ) as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
            assert i == 3
            assert source.sent == 2
            assert data.pi == 'pi'

    else:
        # Test regexes over Python 3 unicode string data (no decode required).  Operates in native
        # unicode symbols.
        source			= cpppo.peekable( 'π' )
        data			= cpppo.dotdict()
        with cpppo.string( 'pi', initial='.*', greedy=True, context='pi' ) as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
            assert i == 2
            assert source.sent == 1
            assert data.pi == 'π'

    source			= cpppo.peekable( str( '123' ))
    data			= cpppo.dotdict()
    with cpppo.integer( 'value' ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 4
        assert source.sent == 3
        assert data.integer == 123


    source			= cpppo.peekable( '123'.encode( 'ascii' ))
    data			= cpppo.dotdict()
    with cpppo.integer_bytes( 'value' ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 4
        assert source.sent == 3
        assert data.integer == 123

    # Try using a integer (str) parser over bytes data.  Works in Python 2, not so much in Python 3
    try:
        source			= cpppo.peekable( '123'.encode( 'ascii' ))
        data			= cpppo.dotdict()
        with cpppo.integer( 'value' ) as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
            assert i == 4
            assert source.sent == 3
            assert data.integer == 123
        assert sys.version_info[0] < 3, \
            "Should have failed in Python3; str/bytes iterator both produce str/int"
    except AssertionError:
        assert not sys.version_info[0] < 3, \
            "Shouldn't have failed in Python2; str/bytes iterator both produce str"

