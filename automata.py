
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

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "GNU General Public License, Version 3 (or later)"

import array
import exceptions
import struct

class state( dict ):
    """
    The basic "null" state, which does not consume an input value, but simply
    transitions to the next appropriate state.
    """
    def __init__( self, name, initial=False, terminal=False ):
        super( state, self ).__init__()
        self.name		= name
        self.terminal		= terminal
        self.recognizers	= []

    def __str__( self ):
        brackets		= 2 if self.terminal else 1
        return '(' * brackets + self.name + ')' * brackets

    def __repr__( self ):
        return '<' + str( self ) + '>'

    # 
    # enter, exit 	-- override to capture state enter and exit
    # 
    #     If the state was terminated by a StopIteration, the state machine was
    # terminated normally in a terminal state, so exit will see complete=True.
    # 
    def __enter__( self ):
        """ The state has been entered """
        self.enter()
    def enter( self ):
        print "%s enter" % ( self )
        pass

    def __exit__( self, type, value, tb ):
        """ The state has been exited """
        self.exit( complete=( type is exceptions.StopIteration ))
    def exit( self, complete ):
        print "%s exit%s" % ( self, " (complete)" if complete else "" )
        pass    

    def __setitem__( self, input, target ):
        """ After ensuring that target is a state, adds a recognizer predicate,
        or defaults to remembering the simple input-->state mapping.
        """
        if not isinstance( target, state ):
            raise KeyError( "Target must be a state" )
        if hasattr( input, '__call__' ):
            self.recognizers.append( (input, target) )
        else:
            super( state, self ).__setitem__( input, target )

    def __getitem__( self, input ):
        """ Default is a dictionary lookup for the target state for input
        (including None, for transitions on no input available), followed by
        testing recognizer predicates, followed by default transition if with
        key "True".  if none found, KeyError.
        """
        try:
            return super( state, self ).__getitem__( input )
        except KeyError:
            if input is not None:
                for predicate,target in self.recognizers:
                    if predicate( input ):
                        return target
                return super( state, self ).__getitem__( True )
            raise
    
    def process( self, source, input=None, machine=None ):
        """ Process the input, raising StopIteration after successfully
        processing in a terminal state.  Otherwise, return the next transition.
        Suitable for use at the end of derived implementations after they have
        processed input, eg:

            return super( derived_class, self ).process( source=source, input=None )
        
        The base implementation itself ignores the input, and uses it to
        transition to the next state.  This is itself useful for selecting one
        of N sub-machines based on an input, without consuming it.  It is still
        a DFA, because there is one edge for each input. """
        if self.terminal:
            raise StopIteration
        return self.transition( source=source, input=input )

    def next_input( self, source, input=None ):
        """ Returns the input, or the next input from source if available.  If
        no input available, raises StopIteration iff this a terminal state;
        otherwise, returns None (allowing no-input transitions). """
        if input is None:
            try:
                input		= next( source )
            except StopIteration:
                if self.terminal:
                    raise
        return input

    def transition( self, source, input=None ):
        """
        Compute the outgoing state.  Returns: (input,state) if a target state
          can be found for the given input, or a no-input [None] transition is
          specified.  The caller will probably want to continue processing the
          input in the new state.

          (input,None) if no target state is found for the input.  The caller
            may want to re-process the input in some other fashion, or raise an
            exception.

          (None,state) if no input is available, but a None transition was
            provided, only to be taken when no input is available.

          (None,None) if no input is available, but not in a terminal state.
            The caller may want to refresh the input source, and continue
            processing in the current state.

          raise StopIteration if no more input is available but we are in a
            terminal state. The caller will likely never call transition
            directly, so we'll never see this; process (above) detects terminal
            states and doesn't invoke transition.  """
        try:
            return (input,self[None])		# Take any NULL (no input) transitions available
        except KeyError:
            # Must have an input; try to get one (raising StopIteration if None,
            # and in a terminal state)
            input		= self.next_input( source=source, input=input )
            try:
                return (input,self[input])	# An input, and a specified transition state/None
            except KeyError:
                return (input,None)		# input/None, and no transition state

    def nodes( self, seen=None ):
        """ Generate all states not yet seen. """
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
        """ Generate (input,state) tuples for all outgoing edges. """
        for pred,target in self.recognizers:
            yield (pred,target)
        for input,target in self.iteritems():
            yield (input,target)

class state_input( state ):
    """ An state that saves its input. """
    def process( self, source, input=None, machine=None ):
        input			= self.next_input( source=source, input=input )
        if input is None:
            return (None,None)			# No input, no transition (not terminal)
        machine.data.append( input )
        return super( state_input, self ).process( source=source, input=None )

class state_struct( state ):
    """ A NULL (no input) state that interprets the preceding states' saved data
    as the specified type.  The default is to assign one unsigned byte, starting
    at offset 1 from the end of the collected data, and assign the result to
    attribute 'value'.  """
    def __init__( self, name, target="value", format="B", offset=1, **kwargs):
        super( state_struct, self ).__init__( name, **kwargs )
        self._target		= target	# property/attribute to get/set
        self._format		= format	# 'struct' format, eg '<H' (little-endian unsigned short)
        self._offset		= offset	# byte offset from end of data
        assert self._target and self._format and self._offset
        
    def process( self, source, input=None, machine=None ):
        setattr( machine, self._target, struct.unpack_from(
            self._format, buffer=machine.data[-self._offset:] )[0] )
        return super( state_struct, self ).process( source=source, input=input )


'''    
class init_attr( state ):
class scan_int( state ):
    """ Parse an integer from input, and transition when done. """
    LITTLE=0
    BIG=NEWORK=1
    def __init__( self, *args, endian=NETWORK, bits=32, **kwargs ):
        super( scan_int, self ).__init__( *args, **kwargs )
        self.endian		= endian
        self.bits		= bits
        assert 0 == bits % 8
        
    def process( )
'''

class dfa( object ):
    """
    Implements a Deterministic Finite Automata, described by the provided set of
    states, rooted at initial.  All input symbols processed since the last reset
    are appended to 'data'.
    """
    def __init__( self, initial=None ):
        self.initial		= initial
        self.reset()

    def reset( self ):
        self.state		= self.initial
        self.data		= array.array('c')	# characters

    def __str__( self ):
        return self.name

    def __repr__( self ):
        return '<' + str( self.name ) + '.' + str( self.state ) + '>'

    @property
    def name( self ):
        return self.__class__.__name__

    def process( self, source, input=None ):
        """
        Process inputs from source, yielding (machine,input,state) transitions
        until a terminal state is reached.  As each new state is entered and
        exited, its __enter__/__exit__ are fired (after being yielded)
        """
        if self.state is None:
            self.reset()
        while self.state is not None:
            trans		= self.state
            with self.state:
                while trans is self.state:
                    # Try to process input and get the next state.  This will
                    # blow out with a StopIteration at a terminal state, after
                    # it processes its input.
                    yield self,input,trans
                    input,trans	= self.state.process( source=source, input=input, machine=self )

            # A different state; just processed last state's '__exit__; change state
            self.state		= trans

        # Non-terminal state, probably no more input
        yield self,input,trans

