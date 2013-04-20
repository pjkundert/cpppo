
# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2013, Hard Consulting Corporation.
# 
# Cpppo is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.  See the LICENSE file at the top of the source tree.
# 
# Cpppo is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 

from __future__ import absolute_import
from __future__ import print_function

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "GNU General Public License, Version 3 (or later)"

import array
try:
    import exceptions
except ImportError:
    pass # No exceptions module for python3
import logging
import struct
import sys
import traceback
try:
    import reprlib
except ImportError:
    import repr as reprlib

from . import misc
from . import greenery
from .dotdict import *

log				= logging.getLogger( __package__ )
log_cfg				= {
    "level":	logging.INFO,
    "datefmt":	'%m-%d %H:%M',
    "format":	'%(asctime)s.%(msecs).03d %(name)-8.8s %(levelname)-8.8s %(funcName)-10.10s %(message)s',
}

# Python2/3 compatibility types, for ascii/unicode str type

# Types produced by iterators over various input stream types
type_bytes_iter			= str if sys.version_info.major < 3 else int
type_str_iter			= str

# The array.array typecode for iterated items of various input stream types
type_str_array_symbol		= 'c' if sys.version_info.major < 3 else 'u'
type_bytes_array_symbol		= 'c' if sys.version_info.major < 3 else 'B'

# Various default data path contexts/extensions
path_ext_input			= '_input'	# default destination input


# If a greenery.fsm (which generally has an alphabet of str symbols), and we
# want to use it on a binary stream of those symbols, we need to encode the
# symbols from the str to the corresponding binary symbol(s).  This will
# basically be a no-op in Python2 (bytes is synonymous with str), but on Python3
# will properly encode the Unicode str symbols to bytes, and then return an
# iterable over the result.
if sys.version_info.major < 3:
    type_str_encoder		= None
else:
    type_str_encoder		= lambda s: ( b for b in s.encode( 'utf-8' ))


def reprargs( *args, **kwds ):
    return ", ".join(   [ reprlib.repr( x ) for x in args ]
                      + [ "%s=%s" % ( k, reprlib.repr( v ))
                          for k,v in kwds.items() ])

def logresult( prefix=None, log=logging ):
    import functools
    def decorator( function ):
        @functools.wraps( function )
        def wrapper( *args, **kwds ):
            try:
                result		= function( *args, **kwds )
                log.debug( "%s-->%r" % (
                        prefix or function.__name__+'('+reprargs( *args, **kwds )+')', result ))
                return result
            except Exception as e:
                log.debug( "%s-->%r" % (
                        prefix or function.__name__+'('+reprargs( *args, **kwds )+')', e ))
                raise
        return wrapper
    return decorator


class lazystr( object ):
    """Evaluates the given function returning a str lazily, eg:
           logging.debug( lazystr( lambda: \
               "Some expensive operation: %d" % ( obj.expensive() )))
       vs.:
           logging.debug(
               "Some expensive operation: %d", obj.expensive() )
    """
    __slots__ = '_function'
    def __init__( self, function ):
        self._function		= function
    def __str__( self ):
        return self._function()

# 
# peekable/peeking
# chainable/chaining
# 
#     Iterator wrappers with the ability to peek ahead and push back unused
# input, and the ability to chain further input iterables to an existing
# chainable iterator.
# 
#     So, user code can simply use the peekable and chainable types.  These will
# detect the required iterator features, and if not present, return an instance
# of the appropriate peeking or chaining class over the provided iterator.
# 
# BACKGROUND
# 
#     When __new__ returns an instance of its cls, standard Python object
# creation invokes its __init__; we don't want to do this, if we detect a
# compatible x-ing iterator (including, specifically, an instance of x-ing
# itself).  Therefore, we cannot simply implement the __new__ classmethod on the
# x-ing class; we must create a different class, called x-able which checks if
# the provided iterator has the required capabilities of an x-ing, and returns
# the original (already compatible) iterator if so.  Otherwise, it creates an
# instance of the required x-ing class over the supplied iterator, and returns
# it.  Since Python detects that x-able's __new__ returned an x-ing instance or
# something like it (certainly not an x-able instance), Python doesn't invoke
# its __init__.
# 
class peekable( object ):
    """Checks that the supplied iterable has (at least) the peek method, and
    returns it if so.  Otherwise, creates a peeking iterator with it."""
    def __new__( cls, iterable=None ):
        if hasattr( iterable, 'peek' ):
            return iterable
        return peeking( iterable=iterable )
    

class chainable( object ):
    """Checks if the supplied iterable is already chaining, and returns it.  If
    not, creates a chaining iterator with it.  This is used by methods expecting
    an iterable with chaining capabilities, to avoid re-wrapping if provided."""
    def __new__( cls, iterable=None ):
        if isinstance( iterable, chaining ):
            return iterable
        return chaining( iterable=iterable )


class peeking( object ):
    """An iterator with peek and push, allowing inspection of the upcoming
    object, and push back of arbitrary numbers of objects.  Also remembers
    how many objects (via next, net push) have been sent."""
    def __init__( self, iterable=None ):
        self._iter		= iter( [] if iterable is None else iterable )
        self._back		= []	# stack of input objects
        self._sent		= 0     # how many objects returned (net)

    @property
    def sent( self ):
        return self._sent

    def __iter__( self ):
        return self

    def push( self, item ):
        self._back.append( item )
        self._sent	       -= 1

    def peek( self ):
        """Returns the next item (if any), otherwise None."""
        if not self._back:
            try:
                self.push( next( self ))
            except StopIteration:
                return None
        return self._back[-1]

    def next( self ):
        return self.__next__()

    def __next__( self ):
        """Returns any items restored by a previous push, then any available
        from the current iterator."""
        try:
            item = self._back.pop() if self._back else next( self._iter )
        except:
            raise
        else:
            self._sent	       += 1
        return item

class chaining( peeking ):
    """An peekable iterator also allowing the chaining of iterables for input.
    Will continuously raise StopIteration at the end of the last iterable; chain
    a non-iterable to terminate any consumers with a TypeError when no more
    input is available to chain."""
    def __init__( self, iterable=None ):
        super( chaining, self ).__init__( iterable=iterable )
        self._chain		= []	# queue of iterators

    def chain( self, iterable ):
        self._chain.insert( 0, iterable )

    def __next__( self ):
        """Returns any items restored by a previous push, then any available
        from the current iterator, then attempts to queue up the next iterator(s)
        and return an item from it.  Will continue to raise StopIteration while
        no more iterables are available.  Load a non-iterable (eg. None) to
        terminate any user gaining input from next( self ) with a TypeError,
        including self.peek().  The failing non-iterable will persist."""
        try:
            result = self._back.pop() if self._back else next( self._iter )
        except StopIteration:
            # Try next chained iterable 'til we find one with something to return
            while self._chain:
                self._iter	= iter( self._chain[-1] )
                self._chain.pop() # iff no exception; else non-iterable persists!
                try:
                    result	= next( self._iter )
                except StopIteration:
                    continue
                else:
                    self._sent += 1
                return result
            # We've run out of iterables, and still no items; re-raise StopIteration
            raise
        else:
            self._sent	       += 1
        return result

class state( dict ):
    """The foundation state class.  A basic Null (no-input) state, which neither
    tests nor consumes an input value, but simply transitions to the next
    appropriate state if a matching transition exists.  Useful for decision
    points, eg:

        q		= state( "Quoted String" )
        q['"']		= quoted_double
        q["'"]		= quoted_single

    Implements the basic state transition generator structure, returning
    non-transition events (machine,None) 'til an input that the state
    accepts/validate is available, then processed, and then an input matching an
    outgoing edge in the underlying dictionary is seen.

    This allows composition of state machines; the higher level machinery runs
    the lower level machine transition generator, passing through state changes
    'til done (StopIteration), watching for non-transition events.  When one
    occurs, the higher level machinery must change the environment (consume the
    next input symbol using its own state machinery, chain fresh input to the
    source input generator, discard the sub-machines and supply the remaining
    input to a new one, ...)
    """
    def __init__( self, name, terminal=False, alphabet=None, context=None, extension=None ):
        super( state, self ).__init__()
        self._name		= name
        self.terminal		= terminal
        self.recognizers	= []
        self._context		= context	# Context added to path with '.'
        self._extension		= extension	#   plus extension, to place output in data
        self.alphabet		= alphabet	# None, type, container or predicate

    @property
    def name( self ):
        return self._name

    def __str__( self ):
        return ( '(' + ( '(' if self.terminal else ' ' ) 
                     + self.name 
                     + ( ')' if self.terminal else ' ' ) + ')' )

    def __repr__( self ):
        return '<%s>' % ( self )

    @property
    def extension( self ):
        return self._extension or '' 

    def context( self, path=None, extension=None ):
        """Yields: 
        Returns the state's data context, optionally joined with the specified path and
        extension "<path>[.<context>]<extension>", eg:

            >>> s.context()
            >>> "boo"
            >>> s.context( path="a.b", extension='_' )
            >>> "a.b.boo_"

        Any path and context are joined with '.', and an extension is just added
        to the base path plus any context."""
        pre			= path or ''
        add			= self._context or ''
        dot			= '.' if ( pre and add ) else ''
        ext			= extension if extension is not None else self.extension
        return pre + dot + add + ext


    # 
    # [x] = <state>	-- Store an outgoing "edge" (input symbol 'x' and target <state>)
    # [x]		-- Find an outgoing transition for symbol 'x', or raise KeyError
    # get(x,<default>)	-- Find an outgoing transition for symbol 'x', or return default
    # 
    def __setitem__( self, inp, target ):
        """After ensuring that target is a state, adds a recognizer predicate,
        or defaults to remembering the simple input-->state mapping."""
        if not isinstance( target, state ):
            raise KeyError( "Target must be a state" )
        if hasattr( inp, '__call__' ):
            self.recognizers.append( (inp, target) )
        else:
            super( state, self ).__setitem__( inp, target )

    def __getitem__( self, inp ):
        """Default is a dictionary lookup for the target state for input from
        most specific to least; the exact input, followed by predicates matching
        an input, followed by default True input transition, and including
        finally None, for transitions on no input available or where no more
        specific input test passes.  If no transition found, raise KeyError."""
        target			= None
        try:
            target		= super( state, self ).__getitem__( inp )
            #log.debug( "%s   [%-10.10r]--> %s", misc.centeraxis( self, 25, clip=True ), inp, target )
            return target
        except KeyError:
            pass
        if inp is not None:
            for pred,target in self.recognizers:
                if pred( inp ):
                    #log.debug( "%s   [%-10.10r]--> %s", misc.centeraxis( self, 25, clip=True ), pred, target )
                    return target
            try:
                target		= super( state, self ).__getitem__( True )
                #log.debug( "%s   [%-10.10r]--> %s", misc.centeraxis( self, 25, clip=True ), True, target )
                return target
            except KeyError:
                pass

        try:
            target		= super( state, self ).__getitem__( None )
            #log.debug( "%s   [%-10.10r]--> %s", misc.centeraxis( self, 25, clip=True ), None, target )
            return target
        except KeyError:
            #log.debug( "%s   [%-10.10r]-x>", misc.centeraxis( self, 25, clip=True ), inp )
            raise

    def get( self, inp, default=None ):
        """The base dict get() doesn't use __getitem__, so we must implement."""
        try:
            return self[inp]
        except KeyError:
            return default
    # 
    # validate		-- Test an input symbol for validity to process
    # accepts		-- Test the upcoming input symbol from source/machine to process
    # process		-- Process the upcoming input symbol
    # 
    def validate( self, inp ):
        """Test input for validity to process.  The base implementation support
        Null (no-input) by accepting None.  Otherwise, the symbol must be
        consistent with the supplied alphabet (if not None); a type, a
        set/list/tuple of symbols, or a predicate."""
        result			= False
        if inp is None or self.alphabet is None:
            result		= True
        elif type( self.alphabet ) is type:
            result		= isinstance( inp, self.alphabet )
        elif hasattr( self.alphabet, '__contains__' ):
            result		= inp in self.alphabet
        elif hasattr( self.alphabet, '__call__' ):
            result		= self.alphabet( inp )
        else:
            raise TypeError("Unknown alphabet: %r" % ( self.alphabet ))
        log.debug( "%s   [%-10.10r]=%s=%r", misc.centeraxis( self, 25, clip=True ),
                    inp, ( "~" if result else "!" ), self.alphabet )
        return result

    def accepts( self, source, machine=None, path=None, data=None ):
        """If input valid returning True, or False to be re-invoked (later) when
        appropriate input is available; default impleentation logs."""
        inp			= source.peek()
        valid			= self.validate( inp )
        log.debug( "%s    %-10.10r:%s", misc.centeraxis( machine, 25, clip=True ),
                inp, "accepted" if valid else "rejected" )
        return valid

    def process( self, source, machine=None, path=None, data=None ):
        """Process the validated input.  The base implementation is a NULL (no
        input consumed) state, which ignores the input (but validates that it is
        either a None or a character).  This is itself useful for selecting one
        of N sub-machines based on an input, without consuming it.  It is still
        a DFA, because there is one edge for each input."""
        pass

    # 
    # run		-- Process input, yield next state/None 'til no more and terminal
    # 
    def run( self, source, machine=None, path=None, data=None, greedy=True ):
        """A generator which will attempt to process input in the present state;
        if not acceptable (self.accepts/self.validate returns False), yields
        non-transition event, and then tries again to process an acceptable
        input.

        Once processed successfully, computes and yields the outgoing state, or
        None if no matching input available, but current state is not terminal.
        If greedy, will continue as long as input is available; otherwise, the
        machine will stop as soon as a terminal state has been reached.


        Loops yielding non-transitions until we've found an input that passes
        accepts/validate to process.  This will allow higher levels of the state
        machine to process pending inputs unrecognized by this machine, allowing
        it to proceed.

        Then, loops yielding non-transitions until we find an outgoing state for
        the pending input symbol (or no transition, but the state is terminal);
        the state is yielded, and the generator completes w/ StopIteration.

        This may seem strange, but we want to keep "punting" (giving higher
        level state machinery a crack at the current unrecognized input symbol)
        'til we're left with one we can handle.  This allows lower level
        machines to process some input and "push" a new symbol (unrecognizable
        to this level, but usable by a higher level), finally proceeding when
        that symbol is processed by the higher level machine.

        All callers must be able to recognize and deal with an infinite stream
        of (machine,None) non-transition tuples yielded by a sub-machine
        presented with unrecognized symbols.  This is the standard failure mode
        of a language grammar parsing failure when presented with a non-matching
        sentence of input: input not recognized, no next state determined, no
        input consumed.

        Yeilds:
          machine,state -- if a target state can be found for the given input, or a
            no-input [None] transition is specified.  The caller will probably
            want to continue processing the input in the new state.

          machine,None -- if no acceptable input is available, and no NULL
            (None/no-input) transition is available.  Indicates that more input
            is required, or that a higher-level state machine may accept and
            process the next input (and then this state machine's generator may
            proceed to process the remaining input).

        Raises:
          StopIteration -- if no more state transitions are available, but we are
            in a terminal state.

          TypeError -- if a non-iterable has been provided to source chainable
            iterator, to force termination of the state machinery."""
        while not self.accepts( source=source, machine=machine, path=path, data=data ):
            yield machine,None
        self.process( source=source, machine=machine, path=path, data=data )

        target			= None
        while target is None:
            inp			= source.peek()		# May raise a TypeError
            target		= self.get( inp, None )
            if target is None or not greedy:
                # No more transitions, or we have more but we aren't greedy: Iff
                # we are in a terminal state, we're done!  This allows us to
                # transition through terminal states while inputs/edges are
                # available, OR stop as soon as a terminal state is reached, if
                # not greedy.
                if self.terminal:
                    break
            '''
            elif target and greedy:
                # If we're greedy and are about to transition from a terminal to
                # a non-terminal state, we are done...  No, we want to eliminate any
                # fsm ransitions going into "dead" states, instead.
                if self.terminal and not target.terminal:
                    break
            '''
            yield machine,target
        # StopIteration after yielding a transition, or if self is a terminal state

    def nodes( self, seen=None ):
        """Generate all states not yet seen."""
        if seen is None:
            seen		= set()
        if id( self ) not in seen:
            seen.add( id( self ))
            yield self
            for _,target in self.recognizers:
                for output in target.nodes( seen=seen ):
                    yield output
            for target in self.values():
                for output in target.nodes( seen=seen ):
                    yield output

    def edges( self ):
        """Generate (input,state) tuples for all outgoing edges."""
        for pred,target in self.recognizers:
            yield (pred,target)
        for inp,target in sorted( self.items(), key=lambda tup: misc.natural( tup[0] )):
            yield (inp,target)

    @classmethod
    def from_fsm( cls, machine, encoder=None, **kwds ):
        """Create a graph of instances of 'cls' (a state class), as specified by
        the given greenery.fsm/lego machine.  All supplied keyword args are pass
        to the 'cls' constructor (eg. context).

        The FSM alphabet is usually native Python str symbols; convert to
        symbols in the target state machine's alphabet when making the
        transitions.  For example, if we want to deal in a stream of bytes, then
        we need to convert the greenery.fsm transition symbols from str to
        str/int (on Python 2/3).  If 'encoder' is supplied, then we can use this
        for the conversion; it must be a generator that produces 1 or more
        encoded symbol for each input symbol.

        An FSM is also designed to be greedy on failure; it will accept and
        consume any unaccepted characters in a final non-terminal state.
        Recognize these states and discard them.

        Returns the resultant regular expression string and lego representation,
        the fsm, and the initial state of the resultant state machine:

            ('regex', <greenery.lego>, <greenery.fsm>, <state>)

        """
        # Accept any of regex/lego/fsm, and build the missing ones.
        regex, lego, initial 	= None, None, None
        if isinstance( machine, str ):
            log.debug( "Converting Regex to greenery.lego: %r", machine )
            regex		= machine
            machine		= greenery.parse( regex )
        if isinstance( machine, greenery.lego ):
            log.debug( "Converting greenery.lego to   fsm: %r", machine )
            lego		= machine
            machine		= lego.fsm()
        if not isinstance( machine, greenery.fsm ):
            raise TypeError("Provide a regular expression, or a greenery.lego/fsm, not: %s %r" % (
                    type( machine ), machine ))
        if lego is None:
            lego		= machine.lego()
        if regex is None:
            regex		= str( lego )

        # Create a state machine identical to the greenery.fsm 'machine'.  There
        # are no "no-input" (NULL) transitions in a greenery.fsm; the None
        # (./anychar) transition is equivalent to the default "True" transition.
        log.debug( "greenery.fsm:\n%s", machine )
        states			= {}
        for pre,tab in machine.map.items():
            terminal		= pre in machine.finals
            log.info( "(%s%s%s) --> %r", 
                      '(' if terminal else ' ', pre, ')' if terminal else ' ', tab.values() )
            if not terminal and all( dst == pre for dst in tab.values() ):
                # Dead state; must check in mapping below...
                log.debug( "dead state %s", pre )
                continue

            states[pre]		= cls( name=str( pre ),
                                       terminal=( pre in machine.finals ),
                                       **kwds )

        # Now, apply the supplied encoder to convert the state machine's symbols
        # (eg. utf-8) into some other input symbols (eg. bytes); if encoder is
        # None, the input symbols are in the same alphabet as the state
        # machine's transition symbols.  If a state machine symbols encode into
        # multiple input symbols, extra (non-terminal) states will be added for
        # each additional symbol.  Can only do this for states/symbols with
        # either no other outgoing transitions, or one "None" (anychar)
        # transition.  We ensure we process the None transition first, so its
        # there in states[pre][True] before processing encoder.
        for pre,tab in machine.map.items():
            for sym in sorted( tab, key=lambda k: [] if k is None else [k] ):
                nxt		= tab[sym]
                if nxt not in states:
                    log.debug( "dead trans %s <- %-10.10r --> %s", pre, sym, nxt )
                    continue
                
                if sym is None:
                    sym		= True
                elif encoder:
                    # Add intervening states for Done; fall thru and link up the
                    # last newly added state to the 'nxt'.  No new states added
                    # or linked if only one symbol results.  We need to find an
                    # unused state number (the map index may not be simple
                    # increasing integers)
                    xformed	= list( enumerate( encoder( sym )))
                    assert len( xformed ) > 0
                    log.debug( "%s <- %-10.10r: Encoded to %r" % (
                                misc.centeraxis( states[pre], 25, clip=True ), sym, xformed ))
                    if len( xformed ) > 1:
                        assert ( 1 <= len( machine.map[pre] ) <= 2 ), \
                            "Can only expand 1 (symbol) or 2 (symbol/anychar) transitions: %r" % (
                                machine.map[pre] )
                        if len( machine.map[pre] ) == 2:
                            assert ( None in machine.map[pre] ), \
                                "If 2 transitions, one must be '.' (anychar): %r" % ( 
                                    machine.map[pre] )

                    # Add and link up additional required states; lst will index
                    # last added one (if any; otherwise it will be pre)
                    lst		= pre
                    for num,enc in xformed[:-1]:
                        add	= len( states )
                        while add in machine.map:
                            add += 1
                        states[add] \
                            	= cls( name=str( pre ) + '_' + str( num ),
                                       terminal=False, **kwds )
                        states[lst][enc] \
                            	= states[add]
                        log.debug( "%s <- %-10.10r -> %s (extra state)",
                                   misc.centeraxis( states[lst], 25, clip=True ), enc, states[add] )
                        if True in states[pre]:
                            states[add][True] \
                                = states[pre][True]
                            log.debug( "%s <- %-10.10r -> %s (dup wild)",
                                       misc.centeraxis( states[add], 25, clip=True ), True, states[pre][True] )
                        lst	= add

                    # If we added extra states, fall thru and link the last
                    # added one (as 'pre') up to 'nxt'
                    num,enc	= xformed[-1]
                    if len( xformed ):
                        pre	= lst
                    sym		= enc
                log.debug( "%s <- %-10.10r -> %s" % (
                        misc.centeraxis( states[pre], 25, clip=True ), sym, states[nxt] ))
                states[pre][sym]=states[nxt]

        initial			= states[machine.initial]
        return (regex, lego, machine, initial)


class state_input( state ):
    """A state that consumes and saves its input symbol by appending it to the
    specified <path>.<context><extension> index/attribute in the supplied data
    artifact.  Creates an array.array of the specified typecode, if no such path
    exists.

    The input alphabet type, and the corresponding array typecode capable of
    containing individual elements of the alphabet must be specified; default is
    str/'c' or str/'u' as appropriate for Python2/3 (the alternative for a
    binary datastream might be bytes/'c' or bytes/'B')."""
    def __init__( self, name, typecode=None, **kwds ):
        # overrides with default if keyword unset OR None
        if kwds.get( "alphabet" ) is None:
            kwds["alphabet"]	= type_str_iter
        if kwds.get( "extension" ) is None:
            kwds["extension"]	= path_ext_input
        self._typecode		= typecode if typecode is not None else type_str_array_symbol
        super( state_input, self ).__init__( name, **kwds )

    def validate( self, inp ):
        """Requires a symbol of input."""
        return inp is not None and super( state_input, self ).validate( inp )

    def process( self, source, machine=None, path=None, data=None ):
        """The raw data is saved to (default): <path>.<context>_input.  The target must
        be an object with a .append() method; if it doesn't exist, an
        array.array will be created with the supplied typecode."""
        inp			= next( source )
        path			= self.context( path=path )
        if data is not None and path:
            if path not in data:
                data[path]	= array.array( self._typecode )
            data[path].append( inp )
            log.info( "%s :  %-10.10r => %20s[%3d]=%r",
                      misc.centeraxis( machine if machine is not None else self, 25, clip=True ),
                       inp, path, len(data[path])-1, inp )


class state_discard( state_input ):
    """Validate and discard a symbol."""
    def process( self, source, machine=None, path=None, data=None ):
        inp			= next( source )
        log.info( "%s :  %-10.10r =x",
                  misc.centeraxis( machine if machine is not None else self, 25, clip=True ),
                  inp )


class state_struct( state ):
    """A NULL (no-input) state that interprets the preceding states' saved symbol
    data as the specified type format.  The default is to assign one unsigned
    byte, starting at offset 1 from the end of the collected symbol data.  The
    raw data is assumed to be at <path>[.<context>]<input_extension> (default:
    '_input', same as state_input)"""
    def __init__( self, name, format=None, offset=1, input_extension=None, **kwds ):
        super( state_struct, self ).__init__( name, **kwds )
        format			= 'B' if format is None else format
        self._struct		= struct.Struct( format ) # eg '<H' (little-endian uint16)
        self._offset		= offset		# byte offset back from end of data
        self._input		= input_extension if input_extension is not None else path_ext_input
        assert self._offset

    def process( self, source, machine=None, path=None, data=None ):
        """Decode a value from path.context_, and store it to path.context.
        Will fail if insufficient data has been collected for struct unpack.
        We'll try first to append it, and then just assign it (creates, if
        necessary)"""
        ours			= self.context( path=path )
        buf			= data[ours+self._input][-self._offset:]
        val		        = self._struct.unpack_from( buffer=buf )[0]
        try:
            data[ours].append( val )
            log.info( "%s :  %-10.10s => %20s[%3d]=%r",
                      misc.centeraxis(  machine if machine is not None else self, 25, clip=True ),
                      "", ours, len(data[ours])-1, val )
        except (AttributeError, KeyError):
            # Target doesn't exist, or isn't a list/deque; just save value
            data[ours]		= val
            log.info( "%s :  %-10.10s => %20s     =%r",
                      misc.centeraxis(  machine if machine is not None else self, 25, clip=True ),
                       "", ours, val )


class dfa( state ):
    """A state which implements a Deterministic Finite Automata, described by
    the provided 'initial' state machine (eg. a graph of state objects).  After
    running the specified state machine to termination for the specified number
    of repeat cycles (default: 1), performs its own transition for its own parent
    state machine.

    By default, a dfa considers itself to be a terminal state; if its state
    sub-machine accepts the sentence, it accepts the sentence."""
    def __init__( self, name=None, initial=None, terminal=True, repeat=None, **kwds ):
        super( dfa, self ).__init__( name or self.__class__.__name__, terminal=terminal, **kwds )
        self.initial		= initial
        assert isinstance( repeat, (str, int, type(None)) )
        self.repeat		= repeat
        for sta in sorted( self.initial.nodes(), key=lambda s: misc.natural( s.name )):
            for inp,dst in sta.edges():
                log.info( "%s <- %-10.10r -> %s", misc.centeraxis( sta, 25, clip=True ), inp, dst )
        self.reset()

    @property
    def name( self ):
        """A dfa's name is its name and a representation of its state."""
        return super( dfa, self ).name + '.' + str( self.current )

    def reset( self ):
        """Invoke to force dfa to recognize a fresh sentence of its grammar."""
        self.current		= None

    def initialize( self, machine=None, path=None, data=None ):
        """Invoked on next loop after the dfa has been reset."""
        self.current		= self.initial
        
        if self.repeat:
            # If there has been a limit on repetitions specified, we need to
            # count.  We'll use a private variable '_cycle' to keep count.
            assert data
            ours		= self.context( path, '_cycle' )
            data[ours]		= 0

    def loop( self, first, machine=None, path=None, data=None ):
        """Determine whether or not to transition the sub-machine; first will be True on
        the initial run, False thereafter.  Normally, this will make the initial
        state the current state, and clear any data context."""
        if self.current is None:
            self.initialize( machine=machine, path=path, data=data )

        if self.repeat:
            # Must be an int, or address an int in our data artifact.  The
            # repeat may resolve to 0, preventing even one loop.  If self.repeat
            # was set, this determines the number of initial-->terminal loop
            # cycles the dfa will execute.
            limit		= self.repeat
            if isinstance( limit, str ):
                limit		= data[self.context( path, limit)]
            assert isinstance( limit, int ), \
                "Supplied repeat=%r must be (or reference) an int, not a %r" % ( self.repeat, limit )
            cycle_path		= self.context( path, '_cycle' )
            cycle		= data[cycle_path]
            assert isinstance( cycle, int ), \
                "Our repeat=%r must be (or reference) an int, not a %r" % ( self.repeat, repeats )
            if cycle >= limit:
                return False
            data[cycle_path] 	= cycle+1
            return True

        # Not self.repeat limited; only execute the first cycle.
        if first:
            return True

        return False

    def run( self, source, machine=None, path=None, data=None, greedy=True ):
        """Yield state transitions until a terminal state is reached (yields
        something with a 'state' attribute), or no more state transitions can be
        processed.  Will end with a terminal state if successful, a None state
        if no more transitions are possible.
        
        A dfa adds its own context to the supplied path before passing it to
        each state via its transition generator.
        """
        source			= peekable( source )

        # Resume in the last state, or in the intial state if we've been reset
        first			= True
        while self.loop( first, machine=machine, path=path, data=data ):
            first		= False	

            yield self,self.current
            armed		= None
            
            # Loop 'til we end up in the same terminal state, making no transitions.
            while armed is not self.current:
                # Try to process input in this state, and get target state.  This
                # may yield an endless stream of (machine,None) if there is no input
                # available and the state has processed; the caller must be prepared
                # to handle this -- if a (_,None) is returned, the caller must
                # either change the conditions (eg. consume an input or chain more
                # input to the source chainable/peekable iterator, or discard this
                # generator)
                armed		= self.current if self.current.terminal else None
                for which,target in self.current.run(
                    source=source, machine=self, path=self.context( path ),
                    data=data, greedy=greedy ):
                    if which is self and target is not None:
                        # This machine made a transition (even if into the same
                        # state!); no longer armed for termination.
                        self.current= target
                        armed	= None
                    yield which,target

            # The sub-machine has reached a terminal state.  We'll leave it in
            # that state, so that if we are re-entered without reset(), we'll
            # continue on transitioning.  For example, if run with greedy=False,
            # we will exit as soon as we first hit a terminal state.


        # Our self.initial state machine has terminated (has ceased performing
        # transitions, and is in a terminal state.)  Perform our own transition
        # (if any).
        for which,target in super( dfa, self ).run(
            source=source, machine=machine, path=path,
            data=data, greedy=greedy ):
            yield which,target

        # Done all sub-machine transitions, and our own transition.


class fsm( dfa ):
    """Takes a regex or greenery.lego/fsm, and converts it to a dfa.  We need to
    specify what type of characters our greenery.fsm operates on; typically,
    normal string.  The semantics of alphabet (an container/type/predicate)
    differs from the greenery alphabet (the exact set of characters used in the
    greenery.lego/fsm).

    When a terminal state is reached in the state machine, the fsm dfa (which
    is, itself a 'state') will process the data, and yield its own transition.
    If no name is supplied, defaults to the greenery.fsm's regex.
    """
    def __init__( self, name=None, initial=None,
                  fsm_states=state_input,
                  fsm_alphabet=type_str_iter,
                  fsm_encoder=None,
                  fsm_typecode=type_str_array_symbol,
                  fsm_context=None, **kwds ):
        assert initial
        regex, lego, machine, initial = fsm_states.from_fsm(
            initial, alphabet=fsm_alphabet, encoder=fsm_encoder, 
            typecode=fsm_typecode, context=fsm_context )
        super( fsm, self ).__init__( name or repr( regex ), initial=initial, **kwds )

class fsm_bytes( fsm ):
    """An fsm is described in str symbols; synonymous for bytes on Python2, but
    utf-8 on Python3 so encode them to bytes, and transform the resultant state
    machine to accept the equivalent sequence of bytes.  Cannot encode machines
    with any more than a single outgoing transition matching any multi-byte
    input symbol (unless the only other transition is '.' (anychar))."""
    def __init__( self,
                  fsm_states=state_input,
                  fsm_alphabet=type_bytes_iter,
                  fsm_encoder=type_str_encoder,
                  fsm_typecode=type_bytes_array_symbol,
                  fsm_context=None, **kwds ):
        super( fsm_bytes, self ).__init__(
                  fsm_states=fsm_states,
                  fsm_alphabet=fsm_alphabet,
                  fsm_encoder=fsm_encoder,
                  fsm_typecode=fsm_typecode, 
                  fsm_context=fsm_context, **kwds )

class fsm_bytes_input( fsm_bytes ):
    """Copy the collected data at path.sub-machine.context_ to our path.context"""
    def process( self, source, machine=None, path=None, data=None ):
        """Once our machine has accepted a sentence of the "echo" grammar and
        terminated, we process it.  It just copies the raw data collected by our
        state machine (we'll use its context), and restarts our sub-machine for
        the next line."""
        ours			= self.context( path )
        subs			= self.initial.context( ours )
        log.info("recv: data[%s] = data[%s]: %r", ours, subs, data[subs] if subs in data else data)
        data[ours]		= data[subs]
        del data[subs]
