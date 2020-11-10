
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

from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import array
import logging
import struct
import sys
import threading
import traceback

import greenery.lego
import greenery.fsm

from . import misc

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


log				= logging.getLogger( __package__ )
log_cfg				= {
    "level":	logging.WARNING,
    "datefmt":	'%m-%d %H:%M:%S',
    "format":	'%(asctime)s.%(msecs).03d %(threadName)10.10s %(name)-8.8s %(levelname)-8.8s %(funcName)-10.10s %(message)s',
}

# Python2/3 compatibility types, for ascii/unicode str type

# Types produced by iterators over various input stream types
type_bytes_iter			= str if sys.version_info[0] < 3 else int
type_str_iter			= str

# The base class of string types
type_str_base			= basestring if sys.version_info[0] < 3 else str

# The array.array typecode for iterated items of various input stream types
type_unicode_array_symbol	= 'u'
type_str_array_symbol		= 'c' if sys.version_info[0] < 3 else 'u'
type_bytes_array_symbol		= 'c' if sys.version_info[0] < 3 else 'B'

# Various default data path contexts/extensions
path_ext_input			= '.input'	# default destination input

# If a greenery.fsm (which generally has an alphabet of str symbols), and we
# want to use it on a binary stream of those symbols, we need to encode the
# symbols from the str to the corresponding binary symbol(s).  This will
# basically be a no-op in Python2 (bytes is synonymous with str), but on Python3
# will properly encode the Unicode str symbols to bytes, and then return an
# iterable over the result.
type_unicode_encoder		= lambda s: ( b for b in s.encode( 'utf-8' ))
type_str_encoder		= None if sys.version_info[0] < 3 else type_unicode_encoder

# 
# is_...
# 
#     Methods for identifying certain types of Python objects
# 
def is_iterator( thing ):
    """Detects if 'thing' is already an iterator/generator."""
    return hasattr( thing, '__next__' if sys.version_info[0] < 3 else 'next' )


def is_listlike( thing ):
    """Something like a list or tuple; indexable, but not a string or a class (some may have
    __getitem__, eg. cpppo.state, based on a dict).

    """
    return not isinstance( thing, (type_str_base,type) ) and hasattr( thing, '__getitem__' )

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
    """Checks that the supplied iterable has (at least) the peek/sent methods, and
    returns it if so.  Otherwise, creates a peeking iterator with it."""
    def __new__( cls, iterable=None ):
        if hasattr( iterable, 'peek' ) and hasattr( iterable, 'sent' ):
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


class rememberable( object ):
    """Checks if the supplied iterable is already remembering, and returns it.  If
    not, creates a remembering iterator with it."""
    def __new__( cls, iterable=None ):
        if isinstance( iterable, remembering ):
            return iterable
        return remembering( iterable=iterable )


class peeking( object ):
    """An iterator with peek and push, allowing inspection of the upcoming
    object, and push back of arbitrary numbers of objects.  Also remembers
    how many objects (via next, net push) have been sent."""
    def __init__( self, iterable=None ):
        self._iter		= iter( [] if iterable is None else iterable )
        self._back		= []	# stack of input objects
        self._sent		= 0     # how many objects returned (net)

    def __repr__( self ):
        return "after %d symbols" % ( self._sent )

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
        """Ensure we invoke the proper super-class __next__ for Python 2/3
        compatibility (ie. cannot simply use 'next = __next__')

        """
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


class remembering( chaining ):
    """A chaining iterator that remembers its yielded symbols.  Can confirm whether items pushed back
    are correct, as well as forget.  Access self.memory property to see previously delivered
    symbols, and call self.forget() to clear."""
    def __init__( self, *args, **kwds ):
        super( remembering, self ).__init__( *args, **kwds )
        self.memory		= []

    def __repr__( self ):
        return super( remembering, self ).__repr__() + ": %r" % ( self.memory )

    def forget( self ):
        self.memory		= []
        
    def __next__( self ):
        result			= super( remembering, self ).__next__()
        self.memory.append( result )
        return result

    def push( self, item ):
        """If we're employing push, it'd better be consistent with our memory!"""
        if self.memory:
            assert self.memory.pop() == item
        super( remembering, self ).push( item )


class decide( object ):
    """A type of object that may be supplied as a state transition target, instead of a state.  It must
    be able to represent itself as a str, and it must have a .state property, and it must be
    callable with machine,source,path,data arguments and return a state or None.

    Decides on a target state if the predicate on machine, path, source and data context is True.

    If the predicate evaluates to not True, or the result of execute is None, the transition
    is deemed to *not* have been taken, and the next state/decide (if any) is used."""
    def __init__( self, name, state=None, predicate=None ):
        self.name		= name
        self.state		= state
        if predicate is None:
            predicate		= lambda **kwds: True 
        self.predicate		= predicate

    def __str__( self ):
        return "%s?%s" % ( self.name, self.state )

    def __repr__( self ):
        return '<%s>' % ( self )

    def __call__( self, machine=None, source=None, path=None, data=None ):
        return self.execute(
            truth=self.predicate( machine=machine, source=source, path=path, data=data ),
            machine=machine, source=source, path=path, data=data )

    def execute( self, truth, machine=None, source=None, path=None, data=None ):
        target			= self.state if truth else None
        #log.debug( "%s %-13.13s -> %10s w/ data: %r", machine.name_centered(), self, target, data )
        return target


class NonTerminal( Exception ):
    """A state machine has been forced to terminate in a non-terminal state"""
    pass


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

    If no transition can be determined based on the next input symbol, more complex transitions can
    be configured, which may access the entire machine state, as well as the input symbol 'source',
    and the 'data' artifact.

    If a limit on the number of possible input symbols is known (or will be known at run-time), it
    can be provided as limit.  Protocols will often include a length field specifying the size of
    the upcoming portion of the protocol; this can be provided to the dfa as a limit, preventing the
    machine from consuming more input than it should.  The ending symbol is computed after this
    state processes its input symbol (if any).  The incoming symbol source iterator's .sent property
    is tested before transitioning, and transitioning is terminated if the computed ending symbol
    has been reached."""

    ANY				= -1 # The [True] default transition on any input 
    NON				= -2 # The [None] fallback transition on no input

    def __init__( self, name, terminal=False, alphabet=None, context=None, extension=None,
                  encoder=None, typecode=None, greedy=True, limit=None ):
        if isinstance( name, state ):
            # Initialization from another state; copy transition dict/recognizers
            other		= name
            super( state, self ).__init__( other )
            self.recognizers	= list( other.recognizers )
            self._name		= other.name + "'"
            self._name_centered	= None
            self._terminal	= other._terminal  if terminal  is None else terminal
            self.alphabet	= other.alphabet   if alphabet  is None else alphabet
            self._context	= other._context   if context   is None else context
            self._extension	= other._extension if extension is None else extension
            self.encoder	= other.encoder    if encoder   is None else encoder
            self.typecode	= other.typecode   if typecode  is None else typecode
            self.greedy		= other.greedy     if greedy    is None else greedy
            self.limit		= other.limit      if limit     is None else limit
        else:
            super( state, self ).__init__()
            self.recognizers	= []
            self._name		= name
            self._name_centered	= None
            self._terminal	= terminal
            self.alphabet	= alphabet	# None, type, container or predicate
            self._context	= context	# Context added to path with '.'
            self._extension	= extension	#   plus extension, to place output in data
            self.encoder	= encoder
            self.typecode	= typecode	# Unused in base, but part of standard interface
            self.greedy		= greedy
            self.limit		= limit

    # Any state evaluates to True (to easily distinguish from None), even if its dict is empty.
    def __nonzero__( self ):
        return True

    __bool__			= __nonzero__	# Python3

    # Make us hashable for use in sets, etc. (and don't define equality in terms of content), even
    # though we're derived from a dict.
    def __hash__( self ):
        return id( self )
    def __eq__( self, other ):
        return self is other
    def __ne__( self, other ):
        return self is not other

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

    def name_centered( self ):
        """Return the 'str' representation of the state centered in a field of whitespace around an axis
        character if any.  Derived classes may enhance the implementation of self.name to include
        other data.

        """
        if self._name_centered is None:
            self._name_centered	= misc.centeraxis(
                self, width=40, clip=True, left_right=lambda w: (w*4//4, w - w*3//4) )
        return self._name_centered

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
        of symbols are used to establish and find transitions.  We do not expect the value None or
        True to appear in input streams, so we will transform them to their place-holder values
        here, for use in setting up the parser tables.

        """
        if inp is True or inp is None:
            return self.ANY if inp else self.NON
        if self.encoder is None:
            return inp
        enc			= tuple( self.encoder( inp ))
        return enc if len( enc ) > 1 else enc[0]

    def __setitem__( self, inp, target ):
        """After ensuring that target is a state or a callable (that should return a state), remember a
        recognizer predicate, or the simple input-->state mapping."""
        if not isinstance( target, state ) and target is not None and not hasattr( target, '__call__' ):
            raise KeyError( "Target must be a state, None, or a state decision function" )
        if hasattr( inp, '__call__' ):
            #log.debug( "%s   [%-10.10r] == %-10s (via %r)", self.name_centered(),
            #           "*", target, inp )
            self.recognizers.append( (inp,target) )
        else:
            # We can allow zero or more "decide" callables followed by zero or one state.
            # Since None and True hash to the same values as 0/1, we'll encode them to
            # -'ve input placeholder symbols that should not appear in valid input.
            enc			= self.encode( inp )
            present		= super( state, self ).setdefault( enc, target )
            if present is not target:
                # Something there already; ensure it's a list, and add new target
                if type( present ) is not list:
                    present	= [ present ]
                present.append( target )
                super( state, self ).__setitem__( enc, present )
            if type( present ) is list:
                # and make sure we only allow: <decide>, ... <decide>, [<state>]
                assert all( not isinstance( v, state ) for v in present[:-1] )
            #log.debug( "%s   [%-10.10s] == %-10s%s", self.name_centered(),
            #           ( "ANY" if enc == self.ANY else "NON" if enc == self.NON else repr( enc )),
            #           present, ( "" if enc is inp else (" (via %s encoding)" % repr( inp ))))

    def __getitem__( self, inp ):
        """Default is a dictionary lookup of the target state, for the encoded input from most specific
        to least; the exact input, followed by predicates matching an input, followed by default
        True input transition, and including finally None, for transitions on no input available or
        where no more specific input test passes.  If no transition found, raise KeyError.  None is
        a valid target.

        This usually returns a <state>, but may return a list: <decide>, ..., <decide>[, <state>]

        Returns None if no transition available.

        Callers may invoke with None/True to detect the presence/absence of an ALL/NON transition.

        """
        enc			= self.encode( inp )
        try:
            return super( state, self ).__getitem__( enc )
        except KeyError:
            pass
        if enc is not self.NON: # Only apply recognizers (and ANY wildcard transition) when input is present
            for pred,target in self.recognizers:
                if pred( enc ):
                    return target
            try:
                return super( state, self ).__getitem__( self.ANY )	# inp not specifically recognized; an ANY tx available?
            except KeyError:
                pass
        return super( state, self ).__getitem__( self.NON )		# inp not available (or no ANY tx); a NON tx available?


    def get( self, inp, default=None ):
        """The base dict get() doesn't use __getitem__, so we must implement it."""
        try:
            return self[inp]
        except KeyError:
            return default

    # Input symbol validation and processing
    def validate( self, inp ):
        """Test input for validity to process.  The base implementation support Null (no-input) by
        accepting None.  Otherwise, the symbol must be consistent with the supplied alphabet (if not
        None); a type, a set/list/tuple of symbols, or a predicate.  This test should be a
        formality; the state machine should only transition into the state on known valid symbols."""
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
        #log.debug( "%s   [%-10.10r]=%s=%r", self.name_centered(),
        #            inp, ( "~" if result else "!" ), self.alphabet )
        return result

    def accepts( self, source, machine=None, path=None, data=None ):
        """If input valid returning True, or False to be re-invoked (later) when appropriate input is
        available; default implematation logs."""
        inp			= source.peek()
        valid			= self.validate( inp )
        #log.debug( "%s    %-10.10r(#%5d): %s", ( machine or self ).name_centered(),
        #           inp, source.sent, "accepted" if valid else "rejected" )

        return valid

    def process( self, source, machine=None, path=None, data=None ):
        """Process the validated input.  The base implementation is a NULL (no input consumed) state,
        which ignores the input.  This is itself useful for selecting one of N sub-machines based on
        an input, without consuming it.  It is still a DFA, because there is one edge for each
        input."""
        pass


    # State transition machinery
    def run( self, source, machine=None, path=None, data=None, ending=None ):
        """A generator which will attempt to process input in the present state; if not acceptable
        (self.accepts/self.validate returns False), yields non-transition event, and then tries
        again to process an acceptable input.

        Once processed successfully, computes and yields the outgoing state, or None if no matching
        input available (or matching input is designated unacceptable by explicit transition to
        None), but current state is not terminal.  If greedy, will continue as long as transitions
        are available; otherwise, the machine will stop as soon as a terminal state reached.

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

        We deal with preventing an infinite of non-transition (machine,None), either due to not
        finding an acceptable input symbol, or not being able to find an acceptable output
        transition, by seeing if we are about to yield the same state, with the exact same input
        symbol and number of symbols sent (a no-progress loop).  In either case, if we're not a
        terminal state, we raise a NonTerminal exception.  This is the standard failure mode of a
        language grammar parsing failure when presented with a non-matching sentence of input: input
        not recognized, no next state determined, no input consumed.

        Yeilds:

          machine,state -- if a target state can be found for the given input, or a no-input [None]
            transition is specified.  The caller will probably want to continue processing the input
            in the new state.

          machine,None -- if no acceptable input is available, and no NULL (None/no-input)
            transition is available.  Indicates that more input is required, or that a higher-level
            state machine may accept and process the next input (and then this state machine's
            generator may proceed to process the remaining input).

        Raises:

          StopIteration	-- if no more state transitions are available, but we're in terminal state.

          TypeError	-- if a non-iterable has been provided to source chainable iterator, to force
            termination of the state machinery.

          NonTerminal	-- if sub-machine terminates in a non-terminal state

        """
        self.safe()

        # Convert the source into something that all delegated generators can consume from and push
        # back onto; this will only only convert a standard iterable to a peekable once.
        source			= peekable( source )

        # We have entered this state; yield 0 or more (machine,None) non-transition events 'til we
        # find an acceptable input.  Higher level machines may choose to consume inputs we cannot,
        # and then either continue accepting output yielded from this generator, or discard it.
        # However, if we get multiple yields with no change in the next symbol or number of symbols
        # sent, we must fail; it is unacceptable to transition into a state and then not process
        # input (use other means to force stoppage before entry, such as input limits or a None
        # transition)
        seen			= set()
        while not self.accepts( source=source, machine=machine, path=path, data=data ):
            crumb		= (None,source.peek(),source.sent)
            assert crumb not in seen, \
                "%s detected no progress before finding acceptable symbol" % ( self )
            seen.add( crumb )
            yield machine,None

        self.process( source=source, machine=machine, path=path, data=data )

        limit = limit_src	= self.limit
        # We have processed input; after this point, we are guaranteed to invoke terminate, and
        # we'll only try to transition if there are no exceptions.
        exception		= None
        try:
            # If instance establishes input source symbol constraints, prepare to enforce them.  Any
            # self.limit supplied may serve to establish or reduce an incoming ending symbol sent
            # amount (never increase it).  The limit is harvested once before running the
            # sub-machine, so it is OK for the referenced limit to disappear during processing
            # (eg. the length erased by new values harvested by the sub-machine).
            if limit is not None:
                if isinstance( limit, type_str_base ):
                    limit_src	= self.context( path, limit_src )
                    limit	= data.get( limit_src, 0 )
                elif hasattr( limit, '__call__' ):
                    limit_src	= misc.function_name( limit )
                    limit	= limit( # provide our machine's context in predicate's path
                        source=source, machine=machine, path=self.context( path ), data=data )
                assert isinstance( limit, int ), \
                    "Supplied limit=%r (== %r) must be (or reference) an int, not a %s" % (
                        limit_src, limit, type( limit ))
                log.info( "%s -- limit=%r == %r; ending at symbol %r vs. %r", self.name_centered(),
                          limit_src, limit, source.sent + limit, ending )
                if ending is None or source.sent + limit < ending:
                    ending	= source.sent + limit 

            # Run the sub-machine; it is assumed that it ensures that sub-machine is deterministic
            # (doesn't enter a no-progress loop).  About 33% of the runtime...
            for which,state in self.delegate(
                    source=source, machine=machine, path=path, data=data, ending=ending ):
                yield which,state
        except GeneratorExit as exc:
            # GeneratorExit is not derived from Exception, to avoid normal except handlers.  If this
            # occurs, the generator has been discarded before completion; we won't be performing our
            # own state transition.  This exception will be masked from self.terminate, if we are in
            # a terminal state, to allow normal termination activities to complete just as if a
            # StopIteration had occurred.
            if not self.terminal:
                log.debug( "%s -- early termination in non-terminal state", self.name_centered() )
                exception	= exc
            else:
                log.info( "%s -- early termination in terminal state; masking GeneratorExit",
                          self.name_centered() )
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
                      repr( exception ), ''.join( traceback.format_exception( typ, exc, tbk )))
            raise
        finally:
            self.terminate( exception, machine=machine, path=path, data=data )

        # If a symbol limit was provided, ensure we haven't exceeded it, and don't transition if
        # we've met it.  We can't decide that here, because we actually want to keep taking None
        # transitions 'til we find a terminal state, even if we've run out of input symbols.  So,
        # pass it down to transition.
        seen			= set()
        for which,state in self.transition(
                source=source, machine=machine, path=path, data=data, ending=ending ):
            crumb		= (state,source.peek(),source.sent)
            if crumb in seen:
                break
            seen.add( crumb )
            yield which,state

        if ending is not None:
            # And finally, make certain we haven't blown our symbol limit, a catastrophic failure.
            assert source.sent <= ending, \
                "%s exceeded limit on incoming symbols by %d" % (
                    self.name_centered(), source.sent - ending )

    def transition( self, source, machine=None, path=None, data=None, ending=None ):
        """We have processed input in a state; now, see if we can find a transition we should yield.
        We may yield 1 or more (machine,None) non-transition events before an input is available to
        decide on a transition.  Remember; a state may have an "epsilon" (no-input) transition; this
        will be taken immediately, even on an input symbol of None (no input available)!  Also, it
        may specify a transition to None (input symbol unacceptable) on any input; this is necessary
        to be able to have sub-machines that reach a terminal state (say, accepting some phrase of
        the grammar), but where the higher-level DFA knows that this phrase is invalid in the
        grammar.

        If not greedy, will cease producing transitions at a terminal state.  If greedy (the
        default), we'll continue to produce transitions until we reach a terminal state and cannot
        transition on the next input symbol.  


        If a state isn't terminal and cannot transition, it may yield non-transition events forever.
        This may seem a bit like OCD, but remember -- this is a base class, and derived classes may
        define self.terminal in complex ways; we may "become" terminal later... Normally, you'd wrap
        a machine made out of 1 or more raw state objects in a dfa (which detects no-progress
        loops), instead of using it directly.

        If a state is greedy and cannot transition, but transition might be possible given the right
        symbol, it must yield non-transitions 'til there is an input symbol available.  Otherwise,
        we cannot know for certain whether or not the state could have transitioned, had there been
        input available.  If we do not wait, the state machine will have different behaviour,
        depending on whether the next input symbol was immediately available, or if we had to yield
        a non-transition to give the caller a chance to acquire input.

        If we've become symbol limited, we must only follow None transitions; we don't want to
        consider the next input symbol at all, because it could lead us down a "choice" path,
        instead of allowing us to successfully stop at  a erminal state.

        TODO: Consider whether we should look for and quit at the first available terminal state,
        once we've become symbol limited (basically, stop being greedy as soon as we're limited).
        This would prevent us from going into "idle" states (ones we want to enter whenever we're
        stopped awaiting input.)  Is this valuable?  We might be able to distinguish between
        "awaiting input" and "limited" in the state machine...

        """
        limited			= ending is not None and source.sent >= ending
        while not self.terminal or self.greedy:
            inp			= None if limited else source.peek()# raise TypeError to force stoppage
            try:
                choice		= self.__getitem__( inp )
            except KeyError:
                # No transition available for current symbol (or None, if no symbol available).  If
                # there is *any* possibility that a transition might be possible if input *were*
                # available, we need to yield a non-transition.
                if limited:
                    log.debug( "%s -- stopped due to reaching symbol limit %d", self.name_centered(), ending )
                elif inp is None and not limited and (
                        self.recognizers or not all( k is None for k in self.keys() )):
                    #log.info( "%s <non  trans>", self.name_centered() )
                    yield machine,None			# 0+ non-transitions...
                    continue
                break					# No other transition possible; done

            # Found the transition or choice list (could be a state, a decide or decide, ...,
            # decide[, state]). Evaluate each target state/decide instance, 'til we find a
            # state/None.  Even decides could end up yielding None, if all decide evaluate to None,
            # and no non-None default state .
            for potential in ( choice if type( choice ) is list else [ choice ] ):
                if potential is None or isinstance( potential, state ):
                    target	= potential
                    break
                try:
                    #log.debug( "%s <selfdecide> on %s", self.name_centered(), choice )
                    target	= potential( # this decision is made in our parent machine's context
                        source=source, machine=machine, path=path, data=data )
                except Exception as exc:
                    log.warning( "%s <selfdecide> on %s failed: %r", self.name_centered(),
                                 potential, exc )
                    raise
                #log.debug( "%s <selfdecide> on %s == %s", self.name_centered(),
                #           potential, target )
                if target:
                    break

            #log.debug( "%s <self trans> into %s", self.name_centered(), target )
            yield machine,target			# 0+ non-transitions, followed by a 1 transition
            break					#   and done!

        # StopIteration after yielding a transition, or if self is a terminal state

    def delegate( self, source, machine=None, path=None, data=None, ending=None ):
        """Base state class delegate generator does nothing; equivalent to `yield from ()` in Python 3.3+"""
        return
        yield

    def initialize( self, machine=None, path=None, data=None ):
        """Done once at state entry."""
        if log.isEnabledFor( logging.DEBUG ):
            log.debug( "%s -- initialized", self.name_centered() )

    def terminate( self, exception, machine=None, path=None, data=None ):
        """Invoked on termination (after yielding our final state transition).  Exception could be:

            None   		Controlled termination after completing final transition.   The terminal
            StopIteration:	condition should be True
        
            GeneratorExit:	The DFA state generator has been discarded.

            Exception, *:	Unknown failure of state machinery.
        """
        if log.isEnabledFor( logging.TRACE ):
            log.trace( "%s -- terminated %s, w/ data: %r", self.name_centered(),
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
            for value in self.values():
                if type( value ) is not list:
                    value	= [ value ]
                for target in value:
                    # None is a valid state/decide target; skip
                    if target is None:
                        continue
                    if not isinstance( target, state ):	# Only state and *.state types allowed
                        target	= target.state
                        if target is None:
                            continue
                    for output in target.nodes( seen=seen ):
                        yield output

    def edges( self ):
        """Generate (input,state|decide) tuples for all outgoing edges."""
        for pred,target in self.recognizers:
            yield (pred,target)
        for inp,target in sorted( self.items(), key=lambda tup: misc.natural( tup[0] )):
            if type( target ) is list:
                for t in target:
                    yield (inp,t)
            else:
                yield (inp,target)

    # Support for producing state machinery from a regular expression specification
    @classmethod
    def from_regex( cls, machine, encoder=None, **kwds ):
        """Create a graph of instances of 'cls' (a state class), as specified by the given textual
        regex or greenery.fsm/lego machine.  All supplied keyword args are pass to the 'cls'
        constructor (eg. context).  The initial state is however always a simple no-input 'state'
        instance, as we do not want to process the first symbol until it has been accepted by the
        regex.

        The greenery.fsm alphabet is usually native Python str symbols; convert to symbols in the
        target state machine's alphabet when making the transitions.  For example, if we want to
        deal in a stream of bytes, then we need to convert the greenery.fsm transition symbols from
        str to str/int (on Python 2/3).  If 'encoder' is supplied, then we can use this for the
        conversion; it must be a generator that produces 1 or more encoded symbol for each input
        symbol.

        A greenery.fsm is also designed to be greedy on failure; it will accept and consume any
        unaccepted characters in a final non-terminal state.  Recognize these dead states and
        drop them; we want to produce a state machine that fails on invalid inputs.

        Returns the resultant regular expression string and lego representation, the fsm, and the
        initial state of the resultant state machine:

            ('regex', <greenery.lego.lego>, <greenery.fsm.fsm>, <state>)

        WARNING: This class method is used in constructors, which may be invoked on module loads;
        do not use logging, as it may not have been set up yet.
        """
        # Accept any of regex/lego/fsm, and build the missing ones.
        regexstr, regex		= None, None
        if isinstance( machine, type_str_base ):
            #log.debug( "Converting Regex to greenery.lego: %r", machine )
            regexstr		= machine
            machine		= greenery.lego.parse( regexstr )
        if isinstance( machine, greenery.lego.lego ):
            #log.debug( "Converting greenery.lego to   fsm: %r", machine )
            regex		= machine
            machine		= regex.fsm()
        if not isinstance( machine, greenery.fsm.fsm ):
            raise TypeError("Provide a regular expression, or a greenery.lego/fsm, not: %s %r" % (
                    type( machine ), machine ))
        if regex is None:
            regex		= machine.lego()
        if regexstr is None:
            regexstr		= str( regex )

        # Create a state machine identical to the greenery.fsm 'machine'.  There are no "no-input"
        # (NULL) transitions in a greenery.fsm; the None (./anychar) transition is equivalent to the
        # default "True" transition.  Detect "dead" states; non-terminal states where all outgoing
        # edges loop back onto itself.  This is used by the greenery state machine to absorb
        # sequences of input that are impossible in the regular expression's grammar, and remain in
        # a non-terminal state.  We want our machine to fail (yield a non-transition) on that input,
        # instead.  So, below, we'll explicitly store a transition to None (a non-transition) for
        # any transition into a dead state.
        #log.debug( "greenery.fsm:\n%s", machine )
        states			= {}
        for pre,tab in machine.map.items():
            terminal		= pre in machine.finals
            initial		= pre == machine.initial
            loopback		= all( dst == pre for dst in tab.values() )
            dead		= loopback and not terminal and not initial

            node		= cls( str( pre ), terminal=terminal, **kwds )
            #log.debug( "%s --> %r %-10s, %-10s, %-10s", node.name_centered(), tab.values(), 
            #          "initial" if initial else "", "terminal" if terminal else "", "dead" if dead else "" )
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
            if pre not in states:
                # These are transitions out of a dead (non-terminal, loopback) state.  Skip them; any
                # symbol after this point is NOT in the grammar defined by the regular expression;
                # yield a non-transition.
                #log.debug( "dead state %s; ignoring", pre )
                continue
            for sym in sorted( tab, key=lambda k: [] if k is None else [k] ):
                nxt		= tab[sym]
                if sym is None:
                    sym		= True
                elif encoder:
                    # Add intervening states for Done; fall thru and link up the last newly added
                    # state to the 'nxt'.  No new states added or linked if only one symbol results.
                    # We need to find an unused state number (the map index may not be simple
                    # increasing integers)
                    xformed	= list( enumerate( encoder( sym )))
                    assert len( xformed ) > 0
                    #log.debug( "%s <- %-10.10r: Encoded to %r", states[pre].name_centered(), sym, xformed )
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
                        #log.debug( "%s <- %-10.10r --> %s (extra state)", states[lst].name_centered(),
                        #           enc, states[add] )
                        if True in states[pre]:
                            states[add][True] \
                                = states[pre][True]
                            #log.debug( "%s <- %-10.10r --> %s (dup wild)", states[add].name_centered(),
                            #           True, states[pre][True] )
                        lst	= add

                    # If we added extra states, fall thru and link the last added one (as 'pre') up
                    # to 'nxt'
                    num,enc	= xformed[-1]
                    if len( xformed ):
                        pre	= lst
                    sym		= enc
                # If this is a transition into a "dead" state, we'll make it an explicit transition
                # to None (a non-transition), forcing the regular expression dfa to cease, rejecting
                # the rest of the symbols.  The dfa will be terminal, iff A) it was marked terminal
                # itself, and B) if the final sub-state was a terminal state.  If there is already a
                # wildcard ('True') transition to None, then we can skip 
                dst		= states.get( nxt ) # will be None if 'nxt' is a "dead" state 
                redundant	= dst is None and states[pre].get( True, True ) is None
                #log.debug( "%s <- %-10.10r --> %s %s", states[pre].name_centered(), sym, dst,
                #           "redundant; skipping" if redundant else "" )
                if redundant:
                    # This symbol targets a dead state (results in a non-Transition), and there is
                    # already a wild-card (True) to a non-transition (None).  Skip it.
                    continue
                states[pre][sym]= dst

        # We create a non-input state copying the initial state's transitions, so we don't consume
        # the first symbol of input before it is accepted by the regex.
        return (regexstr, regex, machine, state( states[machine.initial] ))


class state_input( state ):
    """A state that consumes and saves its input symbol by appending it to the specified
    <path>.<context><extension> index/attribute in the supplied data artifact.  Creates an
    array.array of the specified typecode, if no such path exists.

    The input alphabet type, and the corresponding array typecode capable of containing individual
    elements of the alphabet must be specified; default is str/'c' or str/'u' as appropriate for
    Python2/3 (the alternative for a binary datastream might be bytes/'c' or bytes/'B')."""
    def __init__( self, name, **kwds ):
        # overrides with default if keyword unset OR None
        if kwds.get( "alphabet" ) is None:
            kwds["alphabet"]	= type_str_iter
        if kwds.get( "extension" ) is None:
            kwds["extension"]	= path_ext_input
        if kwds.get( "typecode" ) is None:
            kwds["typecode"]	= type_str_array_symbol
        super( state_input, self ).__init__( name, **kwds )

    def validate( self, inp ):
        """Requires a symbol of input."""
        return inp is not None and super( state_input, self ).validate( inp )

    def process( self, source, machine=None, path=None, data=None ):
        """The raw data is saved to (default): <path>.<context>.input.  The target must be an object
        with a .append() method; if it doesn't exist, an array.array of typecode will be created."""
        inp			= next( source )
        path			= self.context( path=path )
        if path and data is not None:
            try:
                thing		= data[path]
            except KeyError:
                thing = data[path] = array.array( self.typecode )
            thing.append( inp )
            #log.info( "%s :  %-10.10r => %20s[%3d]=%r", ( machine or self ).name_centered(),
            #           inp, path, len(data[path])-1, inp )


class state_drop( state_input ):
    """Validate and drop a symbol."""
    def process( self, source, machine=None, path=None, data=None ):
        inp			= next( source )
        log.debug( "%s :  %-10.10r: dropped", ( machine or self ).name_centered(), inp )


class state_struct( state ):
    """A NULL (no-input) state that interprets the preceding states' saved ....input data as the
    specified struct format (default is one unsigned byte).  The unpacking is starting at an offset
    (default: None) from the start of the collected ....input data, and then at index (default: 0,
    based on the size of the struct format).  For example, to get the 3rd 16-bit little-endian
    UINT16, beginning at offset 1 into the buffer, use format='<H', offset=1, index=2.
    
    The raw data is assumed to be at <path>[.<context>]<input_extension> (default: '.input', same as
    state_input).  Has a .calcsize property (like struct.Struct) which returns the struct format
    size in bytes, as well as .offset and .index properties.

    The default 'struct' format and size is specified by the class-level attribute struct_format and
    struct_calcsize.  If a 'format' keyword is provided to the constructor, then new instance-level
    attributes are specified.  Thus, any method that accesses self.struct_{format,calcsize} will
    obtain either the class-level or instance-level attributes, as appropriate.

    """
    struct_format		= 'B'	# default: unsigned byte
    struct_calcsize		= struct.calcsize( struct_format )

    def __init__( self, name, format=None, offset=0, index=0, input_extension=None, **kwds ):
        super( state_struct, self ).__init__( name, **kwds )
        if format is not None:
            self.struct_format	= format
            self.struct_calcsize= struct.calcsize( self.struct_format )
        self.offset		= offset
        self.index		= index
        assert self.struct_calcsize, "Cannot calculate size of format %r" % self.struct_format
        self._struct		= struct.Struct( self.struct_format )# eg '<H' (little-endian uint16)
        self._input		= input_extension if input_extension is not None else path_ext_input

    def terminate( self, exception, machine=None, path=None, data=None ):
        """Decode a value from path.context_, and store it to path.context.  Will fail if insufficient
        data has been collected for struct unpack.  We'll try first to append it, and then just
        assign it (creates, if necessary)."""

        # Only operate if we have completed without exception.
        super( state_struct, self ).terminate( exception=exception, machine=machine, path=path, data=data )
        ours			= self.context( path=path )
        if exception is not None:
            log.info( "%s: Not decoding struct from %r due to: %r", self.name_centered(), ours, 
                      exception )
            return

        siz			= self.struct_calcsize
        beg			= self.offset + self.index * siz
        end			= beg + siz
        buf			= data[ours+self._input][beg:end]
        val		        = self._struct.unpack_from( buffer=buf )[0]
        try:
            data[ours].append( val )
            if log.isEnabledFor( logging.INFO ):
                log.info( "%s :  %-10.10s => %20s[%3d]= %r (format %r over %r)",
                          ( machine or self ).name_centered(),
                          "", ours, len(data[ours])-1, val, self._struct.format, buf )
        except (AttributeError, KeyError):
            # Target doesn't exist, or isn't a list/deque; just save value
            data[ours]		= val
            log.info( "%s :  %-10.10s => %20s     = %r (format %r over %r)",
                      ( machine or self ).name_centered(),
                      "", ours, val, self._struct.format, buf )


class dfa_base( object ):
    """When used together with a state to make a derived class, implements a Deterministic Finite
    Automata (DFA) described by the provided the 'initial' state of a sub-machine (eg. a graph of
    state objects, potentially including DFAs).

    Unlike a plain state, stores any current operational state (eg. its current state, final repeat
    cycle, etc.) in attributes, so that the same 'dfa' instance may NOT be simultaneously employed
    in multiple state machines.  At least, it may not be in use simultaneously; uses a mutex
    threading.Lock to ensure.

    All states entered by the sub-machine (and its sub-machines) are yielded.  If an input symbol is
    not accepted by the stack of state machines, a (machine,None) transition will be yielded by the
    lower-level machine.

    After running the specified state machine to termination for the specified number of repeat
    cycles (default: 1), performs its own transition for its own parent state machine.  Is only
    considered terminal when instantiated with terminal=True, and its sub-machine is terminal, and
    its final loop is complete.
    """
    def __init__( self, name=None, initial=None, repeat=None, **kwds ):
        super( dfa_base, self ).__init__( name or self.__class__.__name__, **kwds )
        self.current		= initial
        self.initial		= initial
        assert isinstance( repeat, (type_str_base, int, type(None)))
        self.repeat		= repeat
        self.cycle		= 0
        self.final		= 1
        self.lock		= threading.Lock()
        '''
        if log.isEnabledFor( logging.DEBUG ):
            for sta in sorted( self.initial.nodes(), key=lambda s: misc.natural( s.name )):
                for inp,dst in sta.edges():
                    log.debug( "%s <- %-10.10s --> %s", sta.name_centered(),
                               ( "ANY" if inp == self.ANY else "NON" if inp == self.NON else repr( inp )), dst )
        '''
    def __enter__( self ):
        """Must only be in use by a single state machine.  Block 'til we can acquire the lock."""
        # assert self.lock.acquire( False ) is True
        self.lock.acquire()
        return self

    def __exit__( self, typ, val, tbk ):
        self.lock.release()
        return False # suppress no exceptions

    def safe( self ):
        """Ensure that the instance is locked before mutating."""
        assert self.lock.locked() is True, \
            "Attempted to enter a %s.%s w/o locking; lock to ensure use by only one state machine" % (
                __package__, self.__class__.__name__ )

    @property
    def name( self ):
        """A dfa's name is its name and a representation of its state."""
        return super( dfa_base, self ).name + '.' + str( self.current )

    @property
    def terminal( self ):
        """Reflects the terminal condition of this state, our sub-machine, and done all 'repeat' loops.
        If we have a multi-state sub-machine (which may in turn contain further multi-state dfas),
        we must not return terminal 'til A) we ourself were designated as terminal, we are in the
        last loop, and the current state of our multi-state machine is also marked terminal."""
        return self._terminal and self.current.terminal and not self.loop()

    def reset( self ):
        """Done at the start of each loop."""
        if self.current is not self.initial:
            log.debug( "%s -- reset", self.name_centered() )
            self.current	= self.initial

    def loop( self ):
        """Determine whether or not cycles remain before we allow termination of the sub-machine; cycle
        will the be the number of times the sub-machine has been executed to termination thus far.
        If None, default is 1 iteration."""
        return self.cycle < self.final

    def delegate( self, source, machine=None, path=None, data=None, ending=None ):
        """We will generate state transitions from the sub-machine 'til a non-transition (machine,None)
        is yielded (indicating that the input symbol is unacceptable); then (so long as the
        sub-machine is in a terminal state, having accepted the input sentence thus far), we must
        see if we can (as a 'state' ourself) transition on the input symbol; If so, the sub-machine
        is terminated and our transition is yielded instead.  Otherwise, we send the non-transition
        on upwards.

        Runs the inner sub-machine 'til terminal, or if greedy 'til unrecognized symbol.  Each
        sub-machine state may be an individual state instance that will try to process input in the
        state, and get a target state, or a dfa that consists of many states.  This may yield an
        endless stream of (machine,None) if there is no input available, or input is unacceptable;
        the caller (higher-level state machine) must be prepared to handle this -- if a (_,None) is
        returned, the caller must either change the conditions (eg. consume an input or chain more
        input to the source chainable iterator, or discard this generator)."""
        self.cycle		= 0
        self.final		= 1
        final_src		= None
        if self.repeat is not None:
            # Must be an None, int, address an int in our data artifact.  The repeat may resolve to
            # 0/False, preventing even one loop.  If self.repeat was set, this determines the number
            # of initial-->terminal loop cycles the dfa will execute.
            self.final = final_src	= self.repeat
            if isinstance( final_src, type_str_base ):
                # If the final path doesn't exist, default to 0.  This allows us to create composite
                # machines where the first dfa collects the final, and then make an epsilon/None
                # transition to another dfa to collect the specified number of elements.  If the
                # final is missing, no elements will be collected.
                final_src	= self.context( path, final_src )
                self.final	= data.get( final_src, 0 )
                log.debug( "%s -- repeat=%r == %r", self.name_centered(), final_src, self.final )
            assert isinstance( self.final, int ), \
                "Supplied repeat=%r (== %r) must be (or reference) an int, not a %r" % (
                    self.repeat, final_src, self.final )

        # Loop through all required cycles of the sub-machine, unless stasis (no progress) occurs.
        # Unless a cycle of the sub-machine completes, with it reaching a terminal state, we will
        # not advance cycle; hence, self.terminal will remain False on any early exit (eg. due to an
        # early GeneratorExit by a client closing self.run's generator)
        stasis			= False
        while self.loop() and not stasis:
            self.reset()
            self.cycle	       += 1 # On last cycle, sub-machine may be terminated at any terminal state
            #log.debug( "%s <sub  %s> %3d/%3d (from %s)", self.name_centered(), 
            #           "loop" if self.cycle < self.final else "last" , self.cycle, self.final, 
            #           repr( final_src ) if final_src is not None else "(default)" )
            yield self,self.current

            seen		= set( [(self.current,source.peek(),source.sent)] )
            done		= False
            while not done:
                with self.current:
                    submach	= self.current.run(
                        source=source, machine=self, path=self.context( path ), data=data, ending=ending )
                    try:
                        target	= None
                        transit	= False
                        for which,target in submach: # 75% of runtime is spent inside 'run'
                            if which is self:
                                # Watch for loops in our own state sub-machine (lower level dfa's
                                # will watch out for their own sub-machines).  This is the "normal"
                                # method of termination when the sub-machine ceases to be able to
                                # transition, but has been configured as greedy or is non-terminal.
                                # If we end up in the same (<state>,<symbol>,<#sent>); the same
                                # machine/state, with the same pending input, and the same number of
                                # net symbols sent from our input stream, we are done.  We'd better
                                # be in a terminal state!
                                crumb	= (target,source.peek(),source.sent)
                                stasis	= crumb in seen
                                if stasis:
                                    #log.debug( "%s <sub stasis>: done on %s", self.name_centered(),
                                    #           reprlib.repr( crumb ))
                                    done = True
                                    yield which,target
                                    break
                                seen.add( crumb )

                            # A transition or None, and we haven't seen this exact combination
                            # of state and input before.
                            if which is self:
                                #log.debug( "%s <sub  trans> into %s", self.name_centered(), target )
                                if target:
                                    self.current= target
                                    transit	= True
                            else:
                                #log.debug( "%s <deep trans> on %s", self.name_centered(),
                                #           which.name_centered() )
                                pass
                            yield which,target
                        # Our sub-machine is finished transitioning; if our own sub-machine didn't
                        # transition on the (unrecognized) input symbol, we'd better be terminal.
                        # We don't want to break out here, though -- only if we pass up the
                        # non-transition (giving the caller a chance to fill in more data), and then
                        # we see the same (<state>,<symbol>,<#sent>) again, we'll detect that above
                        # and set done to True...  Wrong.  We must *only* run each current state
                        # once, unless it was legitimately transitioned into again!  Otherwise, we'd
                        # be re-running the state's process (probably consuming an input symbol),
                        # just because it produced a non-transition.  If our sub-machine reaches a
                        # state where it can't transit, we're done this loop!  Thus, each state must
                        # make efforts to transit, if it can.  If it detects no input, and it has no
                        # None transition, it *must* yield a non-transition (giving the caller an
                        # opportunity to gain new input), and re-atttempt.
                        if not transit:
                            #log.debug( "%s <sub unrec.>", self.name_centered() )
                            done		= True
                    finally:
                        # Ensure that we guarantee that the sub-machine is forced to terminate
                        # TODO: handle nested exceptions
                        #log.debug( "%s <sub  close>", self.name_centered() )
                        submach.close()

            # At the end of each sub-machine loop, it must be in a terminal state; fails if stasis
            # forced premature termination before all cycles complete, or if done (symbol
            # unrecognized) but sub-machine not in terminal state.  This is an intractable state,
            # sort of similar to what might happen if a state machine produces a transition on a
            # certain symbol, and the accept method passes it, but the state's process method fails
            # to be able to digest it.  A transition into this dfa/state occurred, and some input
            # symbols may be have been recognized, but here we are -- the sub-machine has *not*
            # accepted the sentence in the grammar (it is non-terminal), and we cannot just let the
            # dfa transition away to the next state.  We are forced to indicate failure to accept
            # the sentence with an exception.
            if not self.current.terminal:
                raise NonTerminal( "%s sub-machine terminated in a non-terminal state, %r" % ( self, source ))

        #log.debug( "%s <sub   term>", self.name_centered() )


class dfa( dfa_base, state ):
    pass


class dfa_input( dfa_base, state_input ):
    pass


class dfa_drop( dfa_base, state_drop ):
    pass


class dfa_post( dfa_base, state ):
    """A cpppo.dfa that supports the collection of a FIFO of post-processing closures to invoke when
    the Thread's current invocation of the DFA is complete.  This is sometimes required when one or more
    states in the DFA requires use of the same DFA to process some input.

    If <dfa_post>.lock.locked(), use <dfa_post>.post.append( <closure> ) to schedule the activity
    for immediately after release of the <dfa_post>'s lock.

    When another Thread holds the lock, we must avoid allowing it to process this Thread's closures;
    it may not complete processing them before this Thread expects the results.  Therefore, each Thread
    keeps its own list of closures to process once it releases its own lock.

    """
    def __init__( self, *args, **kwds ):
        # Saves Thread's post-processing callbacks { <ident>: [<callable>, ...] }
        self.post		= {}
        super( dfa_post, self ).__init__( *args, **kwds )

    def post_process_closure( self, closure ):
        """Atomically append a closure to this Thread's list of pending."""
        self.post.setdefault( threading.current_thread().ident, [] ).append( closure )

    def __exit__( self, typ, val, tbk ):
        """After release of the DFA's lock, execute all the post-processing callables.  Allows
        interleaving, by releasing lock between each closure"""
        try:
            return super( dfa_post, self ).__exit__( typ, val, tbk )
        finally:
            while True:
                with self.lock:
                    post_list	= self.post.get( threading.current_thread().ident )
                    if not post_list:
                        break
                    closure	= post_list.pop( 0 )
                # Lock released, got a closure; it may (internally) re-acquire Lock, if necessary.
                try:
                    log.info( "%s -- post-processing %s",
                              self.name_centered(), misc.function_name( closure ))
                    closure()
                except Exception as exc:
                    log.warning( "%s -- post-processing %s failed w/ exception %s\n%s",
                                 self.name_centered(), misc.function_name( closure ),
                                 repr( exc ), ''.join( traceback.format_exc() ))


class regex( dfa ):
    """Takes a regex in string or greenery.lego/fsm form, and converts it to a
    dfa.  We need to specify what type of characters our greenery.fsm
    operates on; typically, normal string.  The semantics of alphabet (an
    container/type/predicate) differs from the greenery alphabet (the exact
    set of characters used in the greenery.lego/fsm).

    When a terminal state is reached in the state machine, the regex dfa (which
    is, itself a 'state') will process the data, and yield its own transition.
    If no name is supplied, defaults to the greenery.fsm's regex.

    The resultant .input array will be character data ('u' in Python 3, 'c' in Python2)
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
    input symbol (unless the only other transition is '.' (anychar)).  

    The resultant .input array will be bytes data ('B' in Python3, 'c' in Python2)."""
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


class string_base( object ):
    r"""When combined with a regex class, collects a string matching the regular expression, and puts it
    in the data artifact at path.context 'string' by default.

    The default initial=".*\n", greedy=False configuration scans input only until the regular
    expression is satisfied (by default, not satisfied 'til it sees a newline) and does no other
    validation, much like the get(3) C library function.

    Other more likely use cases would be to specify specific included character validation, and use
    the greedy=True configuration to scan until the next symbol doesn't satisfy the regular
    expression, or some other feature limits the length of the match:

        initial='.*', greedy=True, length=5	# exactly 5 of any character
        initial='[\w\s]*', greedy=True		# scan letters, numbers, _ and whitespace 'til exhausted
        initial='\d*', greedy=True		# as many digits as can be found

    Alternatively, you could specify regex_alphabet=..., and provide a type, a set/list/tuple of
    acceptable symbols (anything with a __contains__ method), or a function to test the upcoming
    symbol for acceptability.

    If no decode= keyword parameter is provided, it is assumed that the data is already encoded in
    the desired encoding, and doesn't need to be decoded from raw bytes into another encoding.  This
    will generally be the case when the underlying regex is operating on native Python str types
    (ascii or latin-1 in Python 2, utf-8 in Python 3).  When operating on raw bytes, however, a
    target encoding should be provided.  

    In Python 2, it is not possible to differentiate between raw bytes (str) and native
    ascii/latin-1 strings (str).  So, if you're operating in raw bytes and you don't provide an
    encoding, you will be left with a Python str containing the raw bytes; perhaps usable, if the
    data represents information in an 8-bit character set, such as ascii, latin-1/iso-8859-1.  If
    you provide a decode= specification, it will be used -- and yeild (perhaps unexpectedly) a
    Python2 unicode type containing codepoints valid in the specified encoding.

    In Python 3, raw bytes (bytes) and native strings (str, which are utf-8) are distinguishable,
    and you must decode bytes into a specified encoding (eg. iso-8859-1, utf-8, ...) in order to
    yield a python string; if you don't provide a decode= specification, you'll be left with bytes;
    perhaps not what you expect.

    When processing raw bytes data, provide a decode=..., and be prepared to handle the resultant
    unicode/str result.  When processing non-bytes data, you don't have to provide a decode=
    parameter, and the resultant Python str will contain symbols in the original encoding.

    """
    def __init__( self, name, initial=".*", context="string", greedy=False, decode=None, **kwds ):
        self.decode		= decode
        super( string_base, self ).__init__( name=name, initial=initial, context=context,
                                             greedy=greedy, **kwds )

    def terminate( self, exception, machine=None, path=None, data=None ):
        """Once our sub-machine has accepted the specified sequence (into data '<context>.input'),
        convert to an string and store in <context>.  This occurs before outgoing transitions occur.
        Recognize several array typecodes and convert to appropriately convertible string
        representation."""
        ours			= self.context( path )
        if exception is not None:
            log.info( "%s: Not parsing string from %r due to: %r", self.name_centered(), ours,
                      exception )
            return
        subs			= self.initial.context( ours )
        if log.isEnabledFor( logging.INFO ):
            log.info( "%s: data[%s] = data[%s]: %r", self.name_centered(),
                      ours, subs, data.get( subs, data ))
        value			= data[subs]
        if isinstance( value, array.array ):
            if value.typecode == 'c':
                value		= value.tostring() if sys.version_info[0] < 3 else value.tobytes()
            elif value.typecode == 'B':
                value		= value.tobytes()
            elif value.typecode == 'u':
                value		= value.tounicode()
        if self.decode is not None:
            value		= value.decode( self.decode )
        data[ours]		= value


class string( string_base, regex ):
    pass


class string_bytes( string_base, regex_bytes ):
    pass


class integer_base( string_base ):
    """When combined with a regex class, collects a string of digits, and converts them to an integer
    in the data artifact at path.context 'integer' by default. """
    def __init__( self, name, initial=None, context="integer", **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
        super( integer_base, self ).__init__( name=name, initial=r"\d+", context=context,
                                              greedy=True, **kwds )

    def terminate( self, exception, machine=None, path=None, data=None ):
        """Once our sub-machine has accepted a sequence of digits (into data '<context>.input'),
        convert to an integer and store in 'value'.  This occurs before outgoing transitions occur.
        Recognize several array typecodes and convert to appropriately convertible string
        representation."""
        ours			= self.context( path )
        if exception is not None:
            log.info( "%s: Not parsing integer from %r due to: %r", self.name_centered(), ours,
                      exception )
            return

        super( integer_base, self ).terminate(
            exception=exception, machine=machine, path=path, data=data )

        if log.isEnabledFor( logging.INFO ):
            log.info( "%s: int( data[%s]: %r)", self.name_centered(),
                      ours, data.get( ours, data ))
        data[ours]		= int( data[ours] )


class integer( integer_base, regex ):
    pass


class integer_bytes( integer_base, regex_bytes ):
    """Specifying a decode= when processing bytes data is (perhaps strangely) not required, as python's
    int() conversion accepts bytes data containing ascii digits, eg. b'123'.  Therefore, in Python2,
    the integer/integer_bytes are interchangeable.

    In Python3, however, they must be used for str/bytes data respectively, because the underlying
    iterators produce str/int respectively, and so the state machine transitions need to be
    configured based on the different symbol data types.
    """
    pass


class regex_bytes_promote( regex_bytes ):
    """Copy the collected data at path.sub-machine.context to our path.context"""

    def terminate( self, exception, machine=None, path=None, data=None ):
        """Once our machine has accepted a sentence of the grammar and terminated without exception,
        we'll move it to its target location.  It just copies the raw data collected by our state
        machine (we'll use its context).

        Does not delete the original data, but it is quite easy to arrange things such that the
        original location ceases to exist; simply make the destination assign to an element in the
        path to the data, eg::
        
            data.path.context = data.path.context.subcontext.input

        """
        ours			= self.context( path )
        if exception is not None: # If exception in progress, do nothing.
            log.info( "%s: Not copying bytes from %r due to: %r", self.name_centered(), ours,
                      exception )
            return

        subs			= self.initial.context( ours )
        if log.isEnabledFor( logging.INFO ):
            log.info( "data[%s] = data[%s]: %r", ours, subs, data.get( subs, data ))
        data[ours]		= data[subs]
