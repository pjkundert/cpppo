
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
import threading
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
type_unicode_array_symbol	= 'u'
type_str_array_symbol		= 'c' if sys.version_info.major < 3 else 'u'
type_bytes_array_symbol		= 'c' if sys.version_info.major < 3 else 'B'

# Various default data path contexts/extensions
path_ext_input			= '.input'	# default destination input

# If a greenery.fsm (which generally has an alphabet of str symbols), and we
# want to use it on a binary stream of those symbols, we need to encode the
# symbols from the str to the corresponding binary symbol(s).  This will
# basically be a no-op in Python2 (bytes is synonymous with str), but on Python3
# will properly encode the Unicode str symbols to bytes, and then return an
# iterable over the result.
type_unicode_encoder		= lambda s: ( b for b in s.encode( 'utf-8' ))
if sys.version_info.major < 3:
    type_str_encoder		= None
else:
    type_str_encoder		= type_unicode_encoder


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
    """The foundation state class.

    On entry, processes the pending source symbol (if implemented), and then reports the outgoing
    transition state (if any) based on the next source symbol.  If a state requires a source symbol
    to process, it must be available (and acceptable) to process when the state is entered.

    On exit, a state may issue non-transition events (machine, None) when no input symbol is
    available, or when no outgoing transitions are available for the pending source symbol.

    The base 'state' is a Null (no-input) state, which neither tests nor consumes an input value,
    but simply transitions to the next appropriate state if a matching transition exists.  Useful
    for decision points, eg:

        q		= state( "Quoted String" )
        q['"']		= quoted_double
        q["'"]		= quoted_single

    Implements the basic state transition generator structure, returning non-transition events
    (machine,None) 'til an input that the state accepts/validate is available, then processed, and
    then an input matching an outgoing edge in the underlying dictionary is seen.

    This allows composition of state machines; the higher level machinery runs the lower level
    machine transition generator, passing through state changes 'til done (StopIteration), watching
    for non-transition events.  When one occurs, the higher level machinery must change the
    environment (consume the next source symbol using its own state machinery, chain fresh input to
    the source symbol generator, discard the sub-machines and supply the remaining input to a new
    one, ...)

    """
    def __init__( self, name, terminal=False, alphabet=None, context=None, extension=None, encoder=None ):
        if isinstance( name, state ):
            # Initialization from another state; copy transition dict/recognizers
            other		= name
            super( state, self ).__init__( other )
            self.recognizers	= list( other.recognizers )
            self._name		= other.name + "'"
            self._terminal	= other._terminal  if terminal  is None else terminal
            self.alphabet	= other.alphabet   if alphabet  is None else alphabet
            self._context	= other._context   if context   is None else context
            self._extension	= other._extension if extension is None else extension
            self.encoder	= other.encoder    if encoder   is None else encoder
        else:
            super( state, self ).__init__()
            self.recognizers	= []
            self._name		= name
            self._terminal	= terminal
            self.alphabet	= alphabet	# None, type, container or predicate
            self._context	= context	# Context added to path with '.'
            self._extension	= extension	#   plus extension, to place output in data
            self.encoder	= encoder

    # Any state evaluates to True (to easily distinguish from None), even if its dict is empty.
    def __bool__( self ):
        return True
    __nonzero__			= __bool__

    # Support with ..., to enforce mutual exclusion if necessary; the base state retains no
    # information specific to the operation of any one state machine, so may be in simultaneous use.
    def __enter__( self ):
        """May be used by multiple machines simultaneously."""
        return self

    def __exit__( self, typ, val, tbk ):
        return False # suppress no exceptions

    def safe( self ):
        """Confirm that the instance is safe to mutate."""
        pass

    # Support alternative representations in derived classes
    @property
    def name( self ):
        """String representation."""
        return self._name

    def name_centered( self, width=25 ):
        """Lazy string representation, centered around last '.', in given width.  Executes formatting only
        when result is accessed via its __str__ method."""
        return misc.lazystr( lambda: misc.centeraxis( self, width, clip=True ))

    def __str__( self ):
        return ( '(' + ( '(' if self.terminal else ' ' ) 
                     + self.name 
                     + ( ')' if self.terminal else ' ' ) + ')' )

    def __repr__( self ):
        return '<%s>' % ( self )

    @property
    def terminal( self ):
        """Property indicating whether we are in a terminal state; derived classes may have more complex
        procedures for determining this, eg. they may reflect the terminal condition of some other
        state machine."""
        return self._terminal


    # Data context
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
    # encode(inp)	-- Transform the input symbol according to the supplied encoder
    # 
    def encode( self, inp ):
        """All input symbols are encoded using the supplied encoder; the resultant encoded symbol or tuple
        of symbols are used to establish and find transitions."""
        if inp is None or self.encoder is None:
            return inp
        enc			= tuple( self.encoder( inp ))
        return enc if len( enc ) > 1 else enc[0]

    def __setitem__( self, inp, target ):
        """After ensuring that target is a state, remember a recognizer predicate, or the simple
        input-->state mapping."""
        if not isinstance( target, state ) and target is not None:
            raise KeyError( "Target must be a state (or None)" )
        if hasattr( inp, '__call__' ):
            log.debug( "%s   [%-10.10r] == %-10s (via %r)", self.name_centered(),
                       "*", target, inp )
            self.recognizers.append( (inp,target) )
        else:
            enc			= self.encode( inp )
            log.debug( "%s   [%-10.10r] == %-10s%s", self.name_centered(),
                       inp, target, ( "" if enc is inp else (" (via encoding, on %s)" % repr( enc ))))
            super( state, self ).__setitem__( enc, target )

    def __getitem__( self, inp ):
        """Default is a dictionary lookup of the target state, for the encoded input from most specific to
        least; the exact input, followed by predicates matching an input, followed by default True
        input transition, and including finally None, for transitions on no input available or where
        no more specific input test passes.  If no transition found, raise KeyError.  None is a
        valid target."""
        enc			= self.encode( inp )
        try:
            target		= super( state, self ).__getitem__( enc )
            log.debug( "%s   [%-10.10r] == %-10s%s", self.name_centered(),
                       inp, target, ("" if enc is inp else " (via encoding, on %s)" % repr( enc )))
            return target
        except KeyError:
            pass
        if enc is not None:
            for pred,target in self.recognizers:
                if pred( enc ):
                    log.debug( "%s   [%-10.10r] == %-10s (via %r(%r))", self.name_centered(), 
                               inp, target, pred, enc )
                    return target
            try:
                target		= super( state, self ).__getitem__( True )
                log.debug( "%s   [%-10.10r] == %-10s (via wildcard, on %r)", self.name_centered(),
                           inp, target, enc )
                return target
            except KeyError:
                pass
        try:
            target		= super( state, self ).__getitem__( None )
            log.debug( "%s   [%-10.10r] == %-10s (via epsilon,  on %r)", self.name_centered(), inp, target, enc )
            return target
        except KeyError:
            log.debug( "%s   [%-10.10r] xx (no match for %r)", self.name_centered(), inp, enc )
            raise

    def get( self, inp, default=None ):
        """The base dict get() doesn't use __getitem__, so we must implement it."""
        try:
            return self[inp]
        except KeyError:
            return default

    # Input symbol validation and processing
    def validate( self, inp ):
        """Test input for validity to process.  The base implementation support Null (no-input) by accepting
        None.  Otherwise, the symbol must be consistent with the supplied alphabet (if not None); a
        type, a set/list/tuple of symbols, or a predicate.  This test should be a formality; the
        state machine should only transition into the state on known valid symbols."""
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
        log.debug( "%s   [%-10.10r]=%s=%r", self.name_centered(),
                    inp, ( "~" if result else "!" ), self.alphabet )
        return result

    def accepts( self, source, machine=None, path=None, data=None ):
        """If input valid returning True, or False to be re-invoked (later) when appropriate input is
        available; default implematation logs."""
        inp			= source.peek()
        valid			= self.validate( inp )
        log.debug( "%s    %-10.10r: %s", ( machine or self ).name_centered(),
                   inp, "accepted" if valid else "rejected" )

        return valid

    def process( self, source, machine=None, path=None, data=None ):
        """Process the validated input.  The base implementation is a NULL (no input consumed) state, which
        ignores the input.  This is itself useful for selecting one of N sub-machines based on an
        input, without consuming it.  It is still a DFA, because there is one edge for each
        input."""
        pass


    # State transition machinery
    def run( self, source, machine=None, path=None, data=None, greedy=True ):
        """A generator which will attempt to process input in the present state; if not acceptable
        (self.accepts/self.validate returns False), yields non-transition event, and then tries
        again to process an acceptable input.

        Once processed successfully, computes and yields the outgoing state, or None if no matching
        input available (or matching input is designated unacceptable by explicit transition to
        None), but current state is not terminal.  If greedy, will continue as long as input is
        available; otherwise, the machine will stop as soon as a terminal state has been reached.


        Loops yielding non-transition (machine,None) until we've found an input that passes
        accepts/validate to process.  This will allow higher levels of the state machine to process
        pending inputs unrecognized by this machine, allowing it to proceed.

        Then, loops yielding non-transitions until we find an outgoing state for the pending input
        symbol (or no transition, but the state is terminal); the state is yielded, and the
        generator completes w/ StopIteration.

        This may seem strange, but we want to keep "punting" (giving higher level state machinery a
        crack at the current unrecognized input symbol) 'til we're left with one we can handle.
        This allows lower level machines to process some input and "push" a new symbol
        (unrecognizable to this level, but usable by a higher level), finally proceeding when that
        symbol is processed by the higher level machine.

        All callers must be able to recognize and deal with an infinite stream of (machine,None)
        non-transition tuples yielded by a sub-machine presented with unrecognized symbols.  This is
        the standard failure mode of a language grammar parsing failure when presented with a
        non-matching sentence of input: input not recognized, no next state determined, no input
        consumed.

        Yeilds:

          machine,state -- if a target state can be found for the given input, or a no-input [None]
            transition is specified.  The caller will probably want to continue processing the input
            in the new state.

          machine,None -- if no acceptable input is available, and no NULL (None/no-input)
            transition is available.  Indicates that more input is required, or that a higher-level
            state machine may accept and process the next input (and then this state machine's
            generator may proceed to process the remaining input).

        Raises:

          StopIteration -- if no more state transitions are available, but we're in terminal state.

          TypeError -- if a non-iterable has been provided to source chainable iterator, to force
            termination of the state machinery.
        """
        self.safe()

        # Convert the source into something that all delegated generators can consume from and push
        # back onto; this will only only convert a standard iterable to a peekable once.
        source		= peekable( source )

        self.initialize( machine=machine, path=path, data=data )

        # We have been initialized; after this point, we are guaranteed to invoke terminate.
        exception		= None
        try:
            # We have entered this state; yield 0 or more (machine,None) non-transition events 'til we
            # find an acceptable input.  Higher level machines may choose to consume inputs we cannot,
            # and then either continue accepting output yielded from this generator, or discard it.
            while not self.accepts( source=source, machine=machine, path=path, data=data ):
                yield machine,None
            self.process( source=source, machine=machine, path=path, data=data )

            for which,state in self.delegate( 
                    source=source, machine=machine, path=path, data=data, greedy=greedy ):
                yield which,state

            for which,state in self.transition(
                    source=source, machine=machine, path=path, data=data, greedy=greedy ):
                yield which,state
        except GeneratorExit as exc:
            # GeneratorExit is not derived from Exception, to avoid normal except handlers.  If this
            # occurs, the generator has been discarded before completion; we won't be performing our
            # own state transition.
            exception		= exc
            raise
        except Exception as exc:
            # Trap other random Exceptions.  Any Exception will prevent us from processing our own
            # transition; only a clean termination of the above loop (where exception is None) will
            # allow us to proceed to yield our own transitions.
            exception		= exc
            raise
        except:
            # Unknown exception type; probably bad news
            typ, exc, tbk	= sys.exc_info()
            exception		= exc
            log.info( "%s -- failed with unknown exception %s\n%s", self.name_centered(),
                      repr( exception ), ''.join( traceback.format_exception( typ, val, tbk )))
            raise
        finally:
            self.terminate( exception, machine=machine, path=path, data=data )

    def transition( self, source, machine=None, path=None, data=None, greedy=False ):
        """We have processed input in a state; now, see if we can find a transition we should yield.  We may
        yield 1 or more (machine,None) non-transition events before an input is available to decide
        on a transition.  Remember; a state may have an "epsilon" (no-input) transition; this will
        be taken immediately, even on an input symbol of None (no input available)!  Also, it may
        specify a transition to None (input symbol unacceptable) on any input; this is necessary to
        be able to have sub-machines that reach a terminal state (say, accepting some phrase of the
        grammar), but where the higher-level DFA knows that this phrase is invalid in the grammar.

        Normally will cease producing transitions at a terminal state.  If greedy, we'll continue to
        produce transitions until we reach a terminal state and do not recognize the next input
        symbol."""
        while not self.terminal or greedy:		# Loop 'til we find a transition state/None
            inp			= source.peek()		# symbol/None; may raise a TypeError to force stoppage
            try:
                target		= self.__getitem__( inp )
                log.debug( "%s <self trans> to %s", self.name_centered(), target )
                yield machine,target			# 0+ non-transitions, followed by a 1 transition
                break					#   and done!
            except KeyError:				# No transition available;
                if self.terminal:			#   iff we are in a terminal state
                    break   				#      then we're done!
            log.info( "%s <non   trans>", self.name_centered() )
            yield machine,None				# 0+ non-transitions...

        # StopIteration after yielding a transition, or if self is a terminal state

    def delegate( self, source, machine=None, path=None, data=None, greedy=False ):
        """Base state class delegate generator does nothing."""
        raise StopIteration
        yield None 

    def initialize( self, machine=None, path=None, data=None ):
        """Done once at state entry."""
        log.debug( "%s -- initialized", self.name_centered() )

    def terminate( self, exception, machine=None, path=None, data=None ):
        """Invoked on termination (after yielding our final state transition).  Exception could be:

            None   		Controlled termination after completing final transition.   The terminal
            StopIteration:	condition should be True
        
            GeneratorExit:	The DFA state generator has been discarded.

            Exception, *:	Unknown failure of state machinery.
        """
        log.debug( "%s -- terminated %s, w/ data: %r", self.name_centered(),
                   "normally" if exception is None else repr( exception ), data )

    # Traversal of state machine graph
    def nodes( self, seen=None ):
        """Generate all states not yet seen."""
        if seen is None:
            seen		= set()
        if id( self ) not in seen:
            seen.add( id( self ))
            yield self
            for _,target in self.recognizers:
                if target:
                    for output in target.nodes( seen=seen ):
                        yield output
            for target in self.values():
                if target:
                    for output in target.nodes( seen=seen ):
                        yield output

    def edges( self ):
        """Generate (input,state) tuples for all outgoing edges."""
        for pred,target in self.recognizers:
            yield (pred,target)
        for inp,target in sorted( self.items(), key=lambda tup: misc.natural( tup[0] )):
            yield (inp,target)

    # Support for producing state machinery from a regular expression specification
    @classmethod
    def from_regex( cls, machine, encoder=None, **kwds ):
        """Create a graph of instances of 'cls' (a state class), as specified by the given textual regex or
        greenery.fsm/lego machine.  All supplied keyword args are pass to the 'cls' constructor
        (eg. context).  The initial state is however always simple no-input 'state' instance, as we
        do not want to process the first symbol until it has been accepted by the regex.

        The greenery.fsm alphabet is usually native Python str symbols; convert to symbols in the
        target state machine's alphabet when making the transitions.  For example, if we want to
        deal in a stream of bytes, then we need to convert the greenery.fsm transition symbols from
        str to str/int (on Python 2/3).  If 'encoder' is supplied, then we can use this for the
        conversion; it must be a generator that produces 1 or more encoded symbol for each input
        symbol.

        A greenery.fsm is also designed to be greedy on failure; it will accept and consume any
        unaccepted characters in a final non-terminal state.  Recognize these dead states and
        discard them; we want to produce a state machine that fails on invalid inputs.

        Returns the resultant regular expression string and lego representation, the fsm, and the
        initial state of the resultant state machine:

            ('regex', <greenery.lego>, <greenery.fsm>, <state>)

        """
        # Accept any of regex/lego/fsm, and build the missing ones.
        regexstr, lego		= None, None
        if isinstance( machine, basestring if sys.version_info.major < 3 else str ):
            log.debug( "Converting Regex to greenery.lego: %r", machine )
            regexstr		= machine
            machine		= greenery.parse( regexstr )
        if isinstance( machine, greenery.lego ):
            log.debug( "Converting greenery.lego to   fsm: %r", machine )
            lego		= machine
            machine		= lego.fsm()
        if not isinstance( machine, greenery.fsm ):
            raise TypeError("Provide a regular expression, or a greenery.lego/fsm, not: %s %r" % (
                    type( machine ), machine ))
        if lego is None:
            lego		= machine.lego()
        if regexstr is None:
            regexstr		= str( lego )

        # Create a state machine identical to the greenery.fsm 'machine'.  There are no "no-input"
        # (NULL) transitions in a greenery.fsm; the None (./anychar) transition is equivalent to the
        # default "True" transition.
        log.debug( "greenery.fsm:\n%s", machine )
        states			= {}
        for pre,tab in machine.map.items():
            terminal		= pre in machine.finals
            initial		= pre == machine.initial
            loopback		= all( dst == pre for dst in tab.values() )
            dead		= loopback and not terminal and not initial

            node		= cls( str( pre ), terminal=terminal, **kwds )
            log.info( "%s --> %r %-10s, %-10s, %-10s", node.name_centered(), tab.values(), 
                      "initial" if initial else "", "terminal" if terminal else "", "dead" if dead else "" )
            if not dead:
                states[pre]	= node    # must check for dead states in mapping below...

        # Now, apply the supplied encoder to convert the state machine's symbols (eg. utf-8) into
        # some other input symbols (eg. bytes); if encoder is None, the input symbols are in the
        # same alphabet as the state machine's transition symbols.  If a state machine symbols
        # encode into multiple input symbols, extra (non-terminal) states will be added for each
        # additional symbol.  Can only do this for states/symbols with either no other outgoing
        # transitions, or one "None" (anychar) transition.  We ensure we process the None transition
        # first, so its there in states[pre][True] before processing encoder.
        for pre,tab in machine.map.items():
            for sym in sorted( tab, key=lambda k: [] if k is None else [k] ):
                nxt		= tab[sym]
                if nxt not in states:
                    log.debug( "dead trans %s <- %-10.10r --> %s", pre, sym, nxt )
                    continue
                
                if sym is None:
                    sym		= True
                elif encoder:
                    # Add intervening states for Done; fall thru and link up the last newly added
                    # state to the 'nxt'.  No new states added or linked if only one symbol results.
                    # We need to find an unused state number (the map index may not be simple
                    # increasing integers)
                    xformed	= list( enumerate( encoder( sym )))
                    assert len( xformed ) > 0
                    log.debug( "%s <- %-10.10r: Encoded to %r", states[pre].name_centered(), sym, xformed )
                    if len( xformed ) > 1:
                        assert ( 1 <= len( machine.map[pre] ) <= 2 ), \
                            "Can only expand 1 (symbol) or 2 (symbol/anychar) transitions: %r" % (
                                machine.map[pre] )
                        if len( machine.map[pre] ) == 2:
                            assert ( None in machine.map[pre] ), \
                                "If 2 transitions, one must be '.' (anychar): %r" % ( 
                                    machine.map[pre] )

                    # Add and link up additional required states; lst will index last added one (if
                    # any; otherwise it will be pre)
                    lst		= pre
                    for num,enc in xformed[:-1]:
                        add	= len( states )
                        while add in machine.map:
                            add += 1
                        states[add] \
                            	= cls( name=str( pre ) + '_' + str( num ), terminal=False, **kwds )
                        states[lst][enc] \
                            	= states[add]
                        log.debug( "%s <- %-10.10r --> %s (extra state)", states[lst].name_centered(), enc, states[add] )
                        if True in states[pre]:
                            states[add][True] \
                                = states[pre][True]
                            log.debug( "%s <- %-10.10r --> %s (dup wild)", states[add].name_centered(), True, states[pre][True] )
                        lst	= add

                    # If we added extra states, fall thru and link the last added one (as 'pre') up
                    # to 'nxt'
                    num,enc	= xformed[-1]
                    if len( xformed ):
                        pre	= lst
                    sym		= enc
                log.debug( "%s <- %-10.10r --> %s", states[pre].name_centered(), sym, states[nxt] )
                states[pre][sym]=states[nxt]

        # We create a non-input state copying the initial state's transitions, so we don't consume
        # the first symbol of input before it is accepted by the regex.
        return (regexstr, lego, machine, state( states[machine.initial] ))


class state_input( state ):
    """A state that consumes and saves its input symbol by appending it to the specified
    <path>.<context><extension> index/attribute in the supplied data artifact.  Creates an
    array.array of the specified typecode, if no such path exists.

    The input alphabet type, and the corresponding array typecode capable of containing individual
    elements of the alphabet must be specified; default is str/'c' or str/'u' as appropriate for
    Python2/3 (the alternative for a binary datastream might be bytes/'c' or bytes/'B')."""
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
        """The raw data is saved to (default): <path>.<context>.input.  The target must be an object with a
        .append() method; if it doesn't exist, an array.array of typecode will be created."""
        inp			= next( source )
        path			= self.context( path=path )
        if data is not None and path:
            if path not in data:
                data[path]	= array.array( self._typecode )
            data[path].append( inp )
            log.info( "%s :  %-10.10r => %20s[%3d]=%r", ( machine or self ).name_centered(),
                       inp, path, len(data[path])-1, inp )


class state_discard( state_input ):
    """Validate and discard a symbol."""
    def process( self, source, machine=None, path=None, data=None ):
        inp			= next( source )
        log.info( "%s :  %-10.10r: discarded", ( machine or self ).name_centered(), inp )


class state_struct( state ):
    """A NULL (no-input) state that interprets the preceding states' saved ....input data as the
    specified struct format (default is to one unsigned byte).  The unpacking is starting at an
    offset (default: None) from the start of the collected ....input data, and then at index
    (default: 0, based on the size of the struct format).  For example, to get the 3rd 32-bit
    little-endian UINT16, beginning at offset 1 into the buffer, use format='<H', offset=1, index=2.
    
    The raw data is assumed to be at <path>[.<context>]<input_extension> (default: '.input', same as
    state_input).  Has a .calcsize property (like struct.Struct) which returns the struct format
    size in bytes, as well as .offset and .index properties.

    """
    def __init__( self, name, format=None, offset=0, index=0, input_extension=None, **kwds ):
        super( state_struct, self ).__init__( name, **kwds )
        format			= 'B' if format is None else format
        self.offset		= offset
        self.index		= index
        self.calcsize		= struct.calcsize( format )
        assert self.calcsize, "Cannot calculate size of format %r" % format
        self._struct		= struct.Struct( format ) # eg '<H' (little-endian uint16)
        self._input		= input_extension if input_extension is not None else path_ext_input

    def terminate( self, exception, machine=None, path=None, data=None ):
        """Decode a value from path.context_, and store it to path.context.  Will fail if insufficient data
        has been collected for struct unpack.  We'll try first to append it, and then just assign it
        (creates, if necessary)."""

        # Only operate if we have completed without exception.
        super( state_struct, self ).terminate( exception=exception, machine=machine, path=path, data=data )
        if exception is not None:
            return

        ours			= self.context( path=path )
        siz			= self.calcsize
        beg			= self.offset + self.index * siz
        end			= beg + siz
        buf			= data[ours+self._input][beg:end]
        val		        = self._struct.unpack_from( buffer=buf )[0]
        try:
            data[ours].append( val )
            log.info( "%s :  %-10.10s => %20s[%3d]=%r", ( machine or self ).name_centered(),
                      "", ours, len(data[ours])-1, val )
        except (AttributeError, KeyError):
            # Target doesn't exist, or isn't a list/deque; just save value
            data[ours]		= val
            log.info( "%s :  %-10.10s => %20s     =%r", ( machine or self ).name_centered(),
                      "", ours, val )


class dfa_base( object ):
    """When used together with a state to make a derived class, implements a Deterministic Finite
    Automata (DFA) described by the provided the 'initial' state of a sub-machine (eg. a graph of
    state objects, potentially including DFAs).

    Unlike a plain state, stores any current operational state (eg. its current state) in an
    attribute, so that the same 'dfa' instance may NOT be simultaneously employed in multiple state
    machines.  At least, it may not be in use simultaneously; uses a mutex threading.Lock to ensure.

    All states entered by the sub-machine (and its sub-machines) are yielded.  If an input symbol is
    not accepted by the stack of state machines, a (machine,None) transition will be yielded by the
    lower-level machine.

    After running the specified state machine to termination for the specified number of repeat
    cycles (default: 1), performs its own transition for its own parent state machine.  It remains
    in whatever state it terminates, in case the state machine could continue to accept input.

    By default, a dfa considers itself to be a terminal state; if its state sub-machine accepts the
    sentence, it accepts the sentence."""
    def __init__( self, name=None, initial=None, repeat=None, **kwds ):
        assert 'terminal' not in kwds, \
            "The dfa.terminal condition is deduced from the underlying state machine"
        super( dfa_base, self ).__init__( name or self.__class__.__name__, **kwds )
        self.current		= None
        self.initial		= initial
        assert isinstance( repeat, (basestring if sys.version_info.major < 3 else str, int, type(None)) )
        self.repeat		= repeat
        for sta in sorted( self.initial.nodes(), key=lambda s: misc.natural( s.name )):
            for inp,dst in sta.edges():
                log.info( "%s <- %-10.10r --> %s", sta.name_centered(), inp, dst )
        self.lock		= threading.Lock()

    def __enter__( self ):
        """Must only be in use by a single state machine."""
        assert self.lock.acquire( False ) is True
        return self

    def __exit__( self, typ, val, tbk ):
        self.lock.release()
        return False # suppress no exceptions

    def safe( self ):
        """Ensure that the instance is locked before mutating."""
        assert self.lock.locked() is True, \
            "Attempted to enter a %s.%s w/o locking; must lock to ensure use by only one state machine" % (
                __package__, self.__class__.__name__ )

    @property
    def name( self ):
        """A dfa's name is its name and a representation of its state."""
        return super( dfa_base, self ).name + '.' + ( str( self.current ) if self.current else "-" )

    @property
    def terminal( self ):
        """Reflects the terminal condition of our sub-machine."""
        return self.current and self.current.terminal

    def reset( self ):
        """Done at the start of each loop."""
        log.info( "%s -- reset", self.name_centered() )
        self.current		= self.initial

    def loop( self, cycle, machine=None, path=None, data=None ):
        """Determine whether or not to transition the sub-machine; cycle will the be the number of times
        the sub-machine has been executed to termination thus far."""
        if self.repeat:
            # Must be an int, or address an int in our data artifact.  The repeat may resolve to 0,
            # preventing even one loop.  If self.repeat was set, this determines the number of
            # initial-->terminal loop cycles the dfa will execute.
            limit		= self.repeat
            if isinstance( limit, basestring if sys.version_info.major < 3 else str ):
                limit		= data[self.context( path, limit )]
            assert isinstance( limit, int ), \
                "Supplied repeat=%r must be (or reference) an int, not a %r" % ( self.repeat, limit )

            log.info( "%s -- loop %3d/%3d (from %r) %s", self.name_centered(),
                      cycle, limit, self.repeat, "done" if cycle >= limit else "" )
            if cycle >= limit:
                return False
            return True

        # Not self.repeat limited; only execute the initial cycle.
        if cycle == 0:
            return True

        return False

    def delegate( self, source, machine=None, path=None, data=None, greedy=True ):
        """We will generate state transitions from the sub-machine 'til a non-transition (machine,None) is
        yielded (indicating that the input symbol is unacceptable); then (so long as the sub-machine
        is in a terminal state, having accepted the input sentence thus far), we must see if we can
        (as a 'state' ourself) transition on the input symbol; If so, the sub-machine is terminated
        and our transition is yielded instead.  Otherwise, we send the non-transition on upwards.

        Runs the inner sub-machine 'til terminal, or if greedy 'til unrecognized symbol.  Each
        sub-machine state may be an individual state instance that will try to process input in the
        state, and get a target state, or a dfa that consists of many states.  This may yield an
        endless stream of (machine,None) if there is no input available, or input is unacceptable;
        the caller (higher-level state machine) must be prepared to handle this -- if a (_,None) is
        returned, the caller must either change the conditions (eg. consume an input or chain more
        input to the source chainable iterator, or discard this generator)."""
        cycle			= 0
        while self.loop( cycle, machine=machine, path=path, data=data ):
            cycle	       += 1
            self.reset()
            yield self,self.current
            done		= False
            while not done:
                with self.current:
                    submach	= self.current.run(
                        source=source, machine=self, path=self.context( path ), data=data, greedy=greedy )
                    try:
                        seen	= []
                        target	= None
                        transit	= False
                        for which,target in submach:
                            if which is self or target is None:
                                # If we end up in the same (<state>,<symbol>,<#sent>); the same
                                # machine/state, with the same pending input, and the same
                                # number of net symbols sent from our input stream, we are done.
                                # We'd better be in a terminal state!
                                crumb	= (which,target,source.peek(),source.sent)
                                done	= crumb in seen
                                if done:
                                    log.debug( "%s <sub  cycle>: done on %s", self.name_centered(), reprlib.repr( crumb ))
                                    break
                                seen.append( crumb )

                            # A transition or None, and we haven't seen this exact combination
                            # of state and input before.
                            if which is self:
                                log.debug( "%s <sub  trans> to %s", self.name_centered(), target )
                                if target:
                                    self.current= target
                                    transit	= True
                            else:
                                log.debug( "%s <deep trans> on %s", self.name_centered(), which.name_centered() )
                            yield which,target
                        # sub-machine is finished transitioning; if our own sub-machine didn't
                        # transition on the input symbol, we're done
                        if not transit:
                            log.debug( "%s <sub statis>", self.name_centered() )
                            done = True
                    finally:
                        # Ensure that we guarantee that the sub-machine is forced to terminate
                        # TODO: handle nested exceptions
                        log.debug( "%s <sub  close>", self.name_centered() )
                        submach.close()
            log.debug( "%s <sub   done>", self.name_centered() )

            # At the end of each sub-machine run, must be in a terminal state
            assert self.terminal, "DFA state machine terminated in a non-terminal state"

        log.debug( "%s <sub   term>", self.name_centered() )


class dfa( dfa_base, state ):
    pass


class dfa_input( dfa_base, state_input ):
    pass


class dfa_discard( dfa_base, state_discard ):
    pass


class regex( dfa ):
    """Takes a regex in string or greenery.lego/fsm form, and converts it to a
    dfa.  We need to specify what type of characters our greenery.fsm
    operates on; typically, normal string.  The semantics of alphabet (an
    container/type/predicate) differs from the greenery alphabet (the exact
    set of characters used in the greenery.lego/fsm).

    When a terminal state is reached in the state machine, the regex dfa (which
    is, itself a 'state') will process the data, and yield its own transition.
    If no name is supplied, defaults to the greenery.fsm's regex.

    """
    def __init__( self, name=None, initial=None,
                  regex_states=state_input,
                  regex_alphabet=type_str_iter,
                  regex_encoder=None,
                  regex_typecode=type_str_array_symbol,
                  regex_context=None, **kwds ):
        assert initial
        regexstr, lego, machine, initial = regex_states.from_regex(
            initial, alphabet=regex_alphabet, encoder=regex_encoder, 
            typecode=regex_typecode, context=regex_context )
        super( regex, self ).__init__( name or repr( regexstr ), initial=initial, **kwds )


class regex_bytes( regex ):
    """An regex is described in str symbols; synonymous for bytes on Python2, but
    utf-8 on Python3 so encode them to bytes, and transform the resultant state
    machine to accept the equivalent sequence of bytes.  Cannot encode machines
    with any more than a single outgoing transition matching any multi-byte
    input symbol (unless the only other transition is '.' (anychar))."""
    def __init__( self,
                  regex_states=state_input,
                  regex_alphabet=type_bytes_iter,
                  regex_encoder=type_str_encoder,
                  regex_typecode=type_bytes_array_symbol,
                  regex_context=None, **kwds ):
        super( regex_bytes, self ).__init__(
                  regex_states=regex_states,
                  regex_alphabet=regex_alphabet,
                  regex_encoder=regex_encoder,
                  regex_typecode=regex_typecode, 
                  regex_context=regex_context, **kwds )


class regex_bytes_input( regex_bytes ):
    """Copy the collected data at path.sub-machine.context to our path.context"""
    def terminate( self, exception, machine=None, path=None, data=None ):
        """Once our machine has accepted a sentence of the grammar and terminated without exception, we'll
        move it to its target location.  It just copies the raw data collected by our state machine
        (we'll use its context).

        Does not delete the original data, but it is quite easy to arrange things such that the
        original location ceases to exist; simply make the destination assign to an element in the
        path to the data, eg::
        
            data.path.context = data.path.context.subcontext.input

        """
        if exception is not None: # If exception in progress, do nothing.
            return
        super( regex_bytes_input, self ).terminate( exception=exception, machine=machine, path=path, data=data )
        ours			= self.context( path )
        subs			= self.initial.context( ours )
        log.info( "data[%s] = data[%s]: %r", ours, subs, data[subs] if subs in data else data )
        data[ours]		= data[subs]
