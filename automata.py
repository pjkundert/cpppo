
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

_log				= logging.getLogger( "cpppo" )

def reprargs( *args, **kwds ):
    try:
        from repr import repr as repr
    except ImportError:
        from reprlib import repr as repr
    return ", ".join(   [ repr( x ) for x in args ]
                      + [ "%s=%s" % ( k, repr(v) )
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
    object, and push back of arbitrary numbers of objects."""
    def __init__( self, iterable=None ):
        self._iter		= iter( [] if iterable is None else iterable )
        self._back		= []	# stack of input objects

    def __iter__( self ):
        return self

    def push( self, item ):
        self._back.append( item )

    def peek( self ):
        """Returns the next item (if any), otherwise None."""
        if not self._back:
            try:
                self._back.append( next( self ))
            except StopIteration:
                return None
        return self._back[-1]

    def next( self ):
        return self.__next__()

    def __next__( self ):
        """Returns any items restored by a previous push, then any available
        from the current iterator."""
        if self._back:
            return self._back.pop()
        return next( self._iter )


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

    def next( self ):
        return self.__next__()

    def __next__( self ):
        """Returns any items restored by a previous push, then any available
        from the current iterator, then attempts to queue up the next iterator(s)
        and return an item from it.  Will continue to raise StopIteration while
        no more iterables are available.  Load a non-iterable (eg. None) to
        terminate any user gaining input from next( self ) with a TypeError,
        including self.peek().  The failing non-iterable will persist."""
        if self._back:
            return self._back.pop()
        try:
            return next( self._iter )
        except StopIteration:
            # Try next chained iterable 'til we find one with something to return
            while self._chain:
                self._iter	= iter( self._chain[-1] )
                self._chain.pop() # iff no exception; else non-iterable persists!
                try:
                    return next( self._iter )
                except StopIteration:
                    pass
            # We've run out of iterables, and still no items; re-raise StopIteration
            raise

class state( dict ):
    """The foundation state class.  A basic Null (no-input) state, which does
    not consume an input value, but simply transitions to the next appropriate
    state.  Useful for "decision" points, eg:

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
    def __init__( self, name, terminal=False, alphabet=type(next(iter( b'a' ))),
                  context=None ):
        super( state, self ).__init__()
        self.name		= name
        self.terminal		= terminal
        self.recognizers	= []
        self._context		= context  # Context added to path to place product into data
        self.alphabet		= alphabet # type, container or predicate

    def __str__( self ):
        return '(' * ( 1 + self.terminal ) + self.name + ( 1 + self.terminal ) * ')'

    def __repr__( self ):
        return '<%s>' % ( self )

    def context( self, path=None, extension=None ):
        """Returns the context, optionally joined with the specified path and
        extension, eg:

            >>> s.context()
            >>> "boo"
            >>> s.context( path="a.b", extension='_' )
            >>> "a.b.boo_"
        """
        return '.'.join(( [path] if path else [] )
                        + [( self._context or '' ) + ( extension or '')])

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
            _log.debug( "%10.10s.%-15.15s   [%-10.10r]--> %s", "", self, inp, target )
            return target
        except KeyError:
            pass
        if inp is not None:
            for pred,target in self.recognizers:
                if pred( inp ):
                    _log.debug( "%10.10s.%-15.15s   [%-10.10r]--> %s", "", self, pred, target )
                    return target
            try:
                target		= super( state, self ).__getitem__( True )
                _log.debug( "%10.10s.%-15.15s   [%-10.10r]--> %s", "", self, True, target )
                return target
            except KeyError:
                pass

        try:
            target		= super( state, self ).__getitem__( None )
            _log.debug( "%10.10s.%-15.15s   [%-10.10r]--> %s", "", self, None, target )
            return target
        except KeyError:
            _log.debug( "%10.10s.%-15.15s   [%-10.10r]-x>", "", self, inp )
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
        consistent with the supplied alphabet; a type, a set/list/tuple of
        symbols, or a predicate."""
        result			= False
        if inp is None:
            result		= True
        elif type( self.alphabet ) is type:
            result		= isinstance( inp, self.alphabet )
        elif hasattr( self.alphabet, '__contains__' ):
            result		= inp in self.alphabet
        elif hasattr( self.alphabet, '__call__' ):
            result		= self.alphabet( inp )
        else:
            raise TypeError("Unknown alphabet: %r" % ( self.alphabet ))
        _log.debug( "%10.10s.%-15.15s   [%-10.10r]=%s=%r",
                    "", self, inp, ( "~" if result else "!" ), self.alphabet )
        return result

    def accepts( self, source, machine=None, path=None, data=None ):
        """If input valid returning True, or False to be re-invoked (later) when
        appropriate input is available; default impleentation logs."""
        inp			= source.peek()
        valid			= self.validate( inp )
        _log.debug( "%10.10s.%-15.15s    %-10.10r:%s",
                machine, self, inp, "accepted" if valid else "rejected" )
        return valid

    def process( self, source, machine=None, path=None, data=None ):
        """Process the validated input.  The base implementation is a NULL (no
        input consumed) state, which ignores the input (but validates that it is
        either a None or a character).  This is itself useful for selecting one
        of N sub-machines based on an input, without consuming it.  It is still
        a DFA, because there is one edge for each input."""
        pass

    # 
    # transition	-- Process input, yield next state/None 'til no more and terminal
    # 
    def transition( self, source, machine=None, path=None, data=None ):
        """A generator which will attempt to process input in the present state;
        if not acceptable (self.accepts/self.validate returns False), yields
        non-transition event, and then tries again to process an acceptable
        input.

        Once processed successfully, computes and yields the outgoing state, or
        None if no matching input available.  Raises KeyError if acceptable input is
        available but no valid next state is provided (uses provided 'machine'
        for logging only), or some other Exception raised by source iterator.


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
            _log.debug( "%10.10s.%-15.15s<x- %-10.10r", machine, self, source.peek() )
            yield machine,None
        _log.debug( "%10.10s.%-15.15s <- %-10.10r", machine, self, source.peek() )
        self.process( source=source, machine=machine, path=path, data=data )

        target			= None
        while target is None:
            inp			= source.peek()		# May raise a TypeError
            target		= self.get( inp, None )
            if target is None:
                # No target state.  Iff we are in a terminal state, we're done!
                # This allows us to transition through terminal states while
                # inputs/edges are available.
                if self.terminal:
                    break
                _log.debug( "%10.10s.%-15.15s   [%-10.10r]-x>",    machine, self, inp )
            else:
                _log.debug( "%10.10s.%-15.15s   [%-10.10r]--> %s", machine, self, inp, target )
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
        for inp,target in self.items():
            yield (inp,target)


class state_input( state ):
    """A state that consumes and saves its input symbol by appending it to the
    specified path index/attribute in the supplied data artifact.  Creates an
    array.array of the specified datatype, if no such path exists."""
    def __init__( self, name, datatype=None, **kwds ):
        super( state_input, self ).__init__( name, **kwds )
        self.datatype		= ( datatype if datatype is not None
                                    else 'c' if sys.version_info.major < 3
                                    else 'u' )

    def validate( self, inp ):
        """Requires a symbol of input."""
        return inp is not None and super( state_input, self ).validate( inp )

    def process( self, source, machine=None, path=None, data=None ):
        """The raw data is saved to: path.context_"""
        inp			= next( source )
        path			= self.context( path=path, extension='_' )
        _log.info( "%10.10s.%-15.15s :  %-10.10r => %s", machine, self, inp, path )
        if data is not None and path:
            if path not in data:
                data[path]	= array.array( self.datatype )
            data[path].append( inp )


class state_struct( state ):
    """A NULL (no-input) state that interprets the preceding states' saved
    symbol data as the specified type format.  The default is to assign one
    unsigned byte, starting at offset 1 from the end of the collected symbol
    data.  The raw data is assumed to be """
    def __init__( self, name, format="B", offset=1, **kwds ):
        super( state_struct, self ).__init__( name, **kwds )
        self._struct		= struct.Struct( format ) # eg '<H' (little-endian uint16)
        self._offset		= offset		# byte offset back from end of data
        assert self._offset

    def process( self, source, machine=None, path=None, data=None ):
        """Decode a value from path.context_, and store it to path.context.
        Will fail if insufficient data has been collected for struct unpack."""
        path			= self.context( path=path )
        buf			= data[path+'_'][-self._offset:]
        val		        = self._struct.unpack_from( buffer=buf )[0]
        _log.info( "%10.10s.%-15.15s :  .%s=%r", machine, self, path, val )
        data[path]		= val


class dfa( object ):
    """Implements a Deterministic Finite Automata, described by the provided set
    of states, rooted at initial.  All input symbols processed since the last
    reset are appended to 'data'.  The input symbol data type defaults to the
    individual character type of the Python platform 'str': Python3: 'u'
    (unicode character), Python2: 'c' (character)"""
    def __init__( self, name=None, initial=None ):
        self.initial		= initial
        self._name		= name or self.__class__.__name__
        self.reset()

    def reset( self ):
        self.current		= None

    def __str__( self ):
        return self.name

    def __repr__( self ):
        return '<' + str( self.name ) + '.' + str( self.current ) + '>'

    @property
    def name( self ):
        return self._name

    def run( self, source, machine=None, path=None, data=None ):
        """Yield state transitions until a terminal state is reached (yields
        something with a 'state' attribute), or no more state transitions can be
        processed.  Will end with a terminal state if successful, a None state
        if no more transitions are possible."""
        source			= peekable( source )

        # Resume in the last state, or in the intial state if we've been reset
        if self.current is None:
            self.current	= self.initial

        _log.debug( "%10.10s.%-15.15s <- %-10.10r run begins",
                self, self.current, source.peek() )
        yield self,self.current
        armed			= None

        # Loop 'til we end up in the same terminal state, making no transitions.
        while armed is not self.current:
            _log.debug( "%10.10s.%-15.15s <- %-10.10r loop (armed: %r)",
                    self, self.current, source.peek(), armed )
            # Try to process input in this state, and get target state.  This
            # may yield an endless stream of (machine,None) if there is no input
            # available and the state has processed; the caller must be prepared
            # to handle this -- if a (_,None) is returned, the caller must
            # either change the conditions (eg. consume an input or chain more
            # input to the source chainable/peekable iterator, or discard this
            # generator)
            armed		= self.current if self.current.terminal else None
            for machine,target in self.current.transition(
                source=source, machine=self, path=path, data=data ):
                _log.debug( "%10.10s.%-15.15s <- %-10.10r received",
                        machine, target, source.peek() )
                if machine is self and target is not None:
                    # This machine made a transition (even if into the same
                    # state!); no longer armed for termination.
                    self.current= target
                    armed	= None
                yield machine,target

        # No more state transitions available on given input iff state is None
        _log.debug( "%10.10s.%-15.15s <- %-10.10r complete",
                self, self.current, source.peek())


def natural( string ):
    '''
    A natural sort key helper function for sort() and sorted() without
    using regular expressions or exceptions.

    >>> items = ('Z', 'a', '10th', '1st', '9')
    >>> sorted(items)
    ['10th', '1st', '9', 'Z', 'a']
    >>> sorted(items, key=natural)
    ['1st', '9', '10th', 'a', 'Z']    
    '''
    it = type( 1 )
    r = []
    for c in string:
        if c.isdigit():
            d = int( c )
            if r and type( r[-1] ) == it: 
                r[-1] = r[-1] * 10 + d
            else: 
                r.append( d )
        else:
            r.append( c.lower() )
    return r


class fsm( dfa ):
    """Takes a regex or greenery.lego/fsm, and converts it to a dfa.  We need to
    specify what type of characters our greenery.fsm operates on; typically,
    normal string.  The semantics for alphabet differs from the greenery
    alphabet (the exact set of characters used in the greenery.lego/fsm)."""
    def __init__( self, name, initial=None, alphabet=str ):
        super( fsm, self ).__init__( name=name, initial=None )

        import cpppo.greenery as greenery
        import cpppo.misc as misc
        machine			= initial
        if isinstance( machine, type( 'a' )):
            _log.debug( "Converting Regex to greenery.lego: %s", machine )
            machine		= greenery.parse( machine )
        if isinstance( machine, greenery.lego ):
            _log.debug( "Converting greenery.lego to   fsm: %s", machine )
            machine		= machine.fsm()
        if not isinstance( machine, greenery.fsm ):
            raise TypeError("Provide a regular expression, or a greenery.lego/fsm, not: %s %r" % (
                    type( machine ), machine ))

        # Create a state machine identical to the greenery.fsm 'machine'.  There
        # are no "no-input" (NULL) transitions in a greenery.fsm; the None
        # transition is equivalent to the default "True" transition.
        _log.debug( "greenery.fsm:\n%s", machine )
        states			= {}
        for pre in machine.map:
            states[pre]		= state_input( name=str( pre ),
                                               terminal=( pre in machine.finals ),
                                               alphabet=alphabet )
        for pre in machine.map:
            for sym,nxt in machine.map[pre].items():
                states[pre][True if sym is None else sym] \
                    		= states[nxt]

        self.initial		= states[machine.initial]
        _log.info( "cpppo.dfa:" )
        for sta in sorted( self.initial.nodes(), key=lambda s: misc.natural( s.name )):
            for inp,dst in sta.edges():
                _log.info( "           %-15.15s <- %-10.10r -> %s", sta, inp, dst )
        

