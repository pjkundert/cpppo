
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

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

"""
remote.io	-- Interact with remote I/O singularly and in groups
"""

__all__				= ['address', 'input', 'output',
                                   'capture', 'input_event', 'output_event',
                                   'device', 'motor', 'motor_simulator']

import json
import logging
import random

from .. import misc
from ..automata import type_str_base

log				= logging.getLogger( __package__ )

# 
# io.address
# io.input
# io.output
# 
#     PLC value I/O classes.  Provide a .value property with the appropriate
# read-only or read-write accessibility.
# 
class address( object ):
    """ Remembers a PLC address; base class for input and output """
    def __init__( self, plc, address, description=None ):
        self._plc	= plc
        self._address	= address
        self._descr	= ( description if description is not None
                            else "%s/%6d" % ( plc.description, address ))

class input( address ):
    """Instructs the PLC type object to poll the address at a given rate.  Later
    access of the read-only value property will ask the PLC for the value at the
    given address, probably returning the value from the PLC's cache if it is
    online, or None if it is not online.
    """
    def __init__( self, plc, address, description=None, rate=.25 ):
        super( input, self ).__init__( plc, address, description=description )
        plc.poll( address, rate=rate )
        self._last	= None

    def changed( self, last, chng ):
        """ Called when the value is detected to have changed """
        log.info( "%s ==> %-10s (was: %s)" % (
                self._descr, misc.reprlib.repr( chng ), misc.reprlib.repr( last )))

    def _value_get( self ):
        """ Obtain current value, logging if changed.  When a plc is offline, it
        will return None for current value; these are ignored for the purposes
        of recording changed() values."""
        curr		= self._plc.read( self._address )
        if curr is not None and self._last != curr:
            self.changed( self._last, curr )
            self._last	= curr
        return curr
        
    value		= property( _value_get )

class output( input ):
    """ Provides a read-write value property which outputs to the address; uses
    the value setter from input to create a new read-write value property. """

    def __init__( self, plc, address, description=None, rate=.25 ):
        super( output, self ).__init__( plc, address, description=description, rate=rate )

    def rejected( self, last, chng ):
        log.warning( "%s <x= %-10s (now: %s)" % (
                self._descr, misc.reprlib.repr( chng ), misc.reprlib.repr( last )))
        
    def modified( self, last, chng ):
        log.info( "%s <== %-10s (now: %s)" % (
                self._descr, misc.reprlib.repr( chng ), misc.reprlib.repr( last )))

    def _value_set( self, chng ):
        try: 
            self._plc.write( self._address, chng )
        except:
            self.rejected( self._last, chng )
            raise
        self.modified( self._last, chng )

    value		= property( input._value_get, _value_set )

# 
# io.capture
# io.input_event
# io.output_event
# 
#     Capture and remember a series of I/O events.
# 
class capture( object ):
    """ Provide a means to remember an event of type 'what' to an (optionally
    supplied) events container; returned via .events().  The supplied level()
    and formatter() functions take an event type 'what', and the 'last' and
    'chng' values, and return a logging level (0/None to suppress) and formatted
    message.  Must be composed with an 'address' or 'device' class, w/ a '._descr'"""
    
    CHANGED		= 1
    REJECTED		= 2
    MODIFIED		= 3

    def __init__( self, retain=None, group=None, level=None, formatter=None ):
        self._events	= []
        self._retain	= retain
        self._group	= "" if group is None else group
        self._level	= level	     # May be None/0 (don't collect), int or function(what, last, curr)
        self._formatter	= formatter  # May be None (logs values), or a function(what, last, curr)

    def remember( self, what, last, chng ):
        """ All new events are prepended (inserted at index 0) to the ._events
        container, so newest events appear earliest. """
        if self._events is not None:
            level	= ( self._level( what, last, chng )
                            if hasattr( self._level, '__call__' )
                            else self._level )
            if level is not None and level >= 0: # may be +'ve/0/None, or -'ve (ignored)
                message	= ( self._formatter( what, last, chng )
                            if self._formatter
                            else "%s (was %s)" % ( misc.reprlib.repr( chng ), misc.reprlib.repr( last )))
                self._events.insert( 0, { 
                        "time":		misc.timer(),
                        "level":	level,
                        "group":	self._group,
                        "description":	self._descr, # comes from a device/address composed with this class
                        "message":	message,
                        } )

    def events( self, since=None, purge=False ):
        """ A generator yielding the stream of relevant events (None if since is
        None, otherwise limited to those with a ["time"] strictly greater than
        'since'), optionally purging as we go; if we complete the iteration, our
        ._events will be replaced with the retain list.  This is not a property,
        because it doesn't return simple value, and we want to (optionally)
        purge the internal _events list, or provide a 'since' time."""
        unique		= set()
        retain		= []
        now	        = misc.timer()
        for e in self._events:
            if self._retain:
                if e["description"] not in unique:
                    unique.add( e["description"] )
                else:
                    if e["time"] + self._retain < now:
                        # old event, and we've seen this description before; skip
                        log.debug( "Purging event: %r" % ( e ))
                        continue
                retain.append( e )
            if since is not None and e["time"] > since:
                yield e
        if self._retain:
            self._events= retain


class input_event( input, capture ):
    """ An input that captures changed events """
    def __init__( self, plc, address, 
                  retain=None, group=None, level=None, formatter=None, **kwargs ):
        capture.__init__( self, retain=retain, group=group, level=level, formatter=formatter )
        input.__init__( self, plc, address, **kwargs )

    def changed( self, last, chng ):
        self.remember( what=capture.CHANGED, last=last, chng=chng )
        return super( input_event, self ).changed( last=last, chng=chng )


class output_event( output, capture ):
    """ An output that captures changed/rejected/modified events """
    def __init__( self, plc, address, 
                  retain=None, group=None, level=None, formatter=None, **kwargs ):
        capture.__init__( self, retain=retain, group=group, level=level, formatter=formatter )
        output.__init__( self, plc, address, **kwargs )

    def changed( self, last, chng ):
        self.remember( what=capture.CHANGED, last=last, chng=chng )
        return super( output_event, self ).changed( last=last, chng=chng )

    def rejected( self, last, chng ):
        self.remember( what=capture.REJECTED, last=last, chng=chng )
        return super( output_event, self ).rejected( last=last, chng=chng )

    def modified( self, last, chng ):
        self.remember( what=capture.MODIFIED, last=last, chng=chng )
        return super( output_event, self ).modified( last=last, chng=chng )


# 
# io.device
# io.motor
# io.motor_simulator
# 
#     Devices controlled/monitored by multiple I/O
# 
class device( object ):
    """A device has attributes; some are read-only, and some are read-write.
    The default device has read-only group, identity (unique) and description
    (human-readable identification) attributes.
    """
    def __init__( self, group, identity, description ):
        self._group	= group
        self._ident	= identity
        self._descr	= description

    @property
    def group( self ):
        return self._group

    @property
    def identity( self ):
        return self._ident

    @property
    def description( self ):
        return self._descr

    def __str__( self ):
        pairs		= dict( (a, getattr( self, a ))
                                for a in dir( self ) if not a.startswith('_') and a != "events" )
        return json.dumps( pairs, sort_keys=True, indent=4 )

    __repr__ 		= __str__

        
class motor( device ):
    """ A motor is a device that represents a Motor status.  It requires a PLC
    poller object that contains 5 addresses:

    auto	-- The input for Hand/Off/Auto switch position; True iff Auto
    run		-- The input for Motor Running; True iff motor is running
    start	-- The output for Motor Start; Write True to start, False to stop
    fault	-- The input for Motor Fault; False iff motor has faulted
    reset	--   write True to reset fault; PLC will clear in response
    estop	-- The input for E-Stop; True if E-Stop is Clear

    The motor.events captures the supplied 'events' argument, into which are fed
    all the relevant motor I/O events, and other internally detected events, as
    a list of dicts, each containing a "time", "level", group" "description" and
    "message" entry (at least).  Only 5 minutes of events are retained in full
    detail (or the last event for each unique "description", if older)
    
    """

    def __init__( self, group, identity, description, 
                  plc, auto, running, start, fault, estop, reset,  rate=.25,
                  events=None, retain=5*60 ):
        super( motor, self ).__init__( group, identity, description )

        def level_filter( what, last, chng ):
            """ By default, don't log None changes (comm fail), and log cleared
            values at the lowest level NOTSET, and set values at INFO (written
            values are logged likewise, but one logging level higher).  Rejected
            writes are logged at ERROR """
            if what in (capture.REJECTED, ):
                return logging.ERROR
            if what in (capture.MODIFIED, ):
                return logging.WARNING if chng else logging.INFO
            if chng is not None:
                return logging.INFO if chng else logging.NOTSET
            return None # capture.CHANGED, but just offline

        def level_base( base ):
            """ Offset any returned non-None levels by the given base.  In other
            words, the incoming "0" value has the given 'base' logging level,
            other events go up from there. """
            def filter( what, last, chng ):
                level	= level_filter( what, last, chng )
                return None if level is None else base + level
            return filter

        # Attributes with .value property read-only/read-write as appropriate.
        self._auto	= input_event(
            plc, address=auto,    rate=rate, 
            description="%6s.%-6s" % ( self.identity, "auto" ),
            retain=retain, group=group, level=level_filter,
            formatter=lambda what,last,chng: \
                ( "Auto"              if chng else "Hand" ))
        self._running	= input_event(
            plc, address=running, rate=rate,
            description="%6s.%-6s" % ( self.identity, "run" ),
            retain=retain, group=group, level=level_filter,
            formatter=lambda what,last,chng: \
                ( "On"                if chng else "Off" ))
        # Since fault is -'ve logic, we'll use the standard level function, but
        # invert the arguments (so that a False (Faulted) signal will produce a
        # higher logging level than a True (Cleared) signal)
        level_fault_base= level_base( logging.WARNING )
        level_fault	= lambda what,last,chng: \
            level_fault_base( what,
                              None if last is None else not last,
                              None if chng is None else not chng )
        self._fault	= input_event(
            plc, address=fault,   rate=rate,
            description="%6s.%-6s" % ( self.identity, "fault" ),
            retain=retain, group=group, level=level_fault,
            formatter=lambda what,last,chng: \
                ( "Faulted Cleared"   if chng else "Fault" ))	# -'ve logic
        self._estop	= input_event(
            plc, address=estop,   rate=rate,
            description="%6s.%-6s" % ( self.identity, "estop" ),
            retain=retain, group=group, level=level_base( logging.WARNING ),
            formatter=lambda what,last,chng: \
                ( "E-Stop"           if chng else "E-Stop Cleared" ))
        self._start	= output_event(
            plc, address=start,   rate=rate,
            description="%6s.%-6s" % ( self.identity, "start" ),
            retain=retain, group=group, level=level_base( 0 ),
            formatter=lambda what,last,chng: \
                ( "Start Sent"        if what==capture.MODIFIED and chng and not last
                  else "Stop Sent"    if what==capture.MODIFIED and last and not chng
                  else "Started"      if chng
                  else "Stopped" ))
        self._reset	= output_event(
            plc, address=reset,   rate=rate,
            description="%6s.%-6s" % ( self.identity, "reset" ),
            retain=retain, group=group, level=level_filter,
            formatter=lambda what,last,chng: \
                ( "Reset Sent"        if what==capture.MODIFIED and chng and not last
                  else "Reset Disarm" if what==capture.MODIFIED and last and not chng
                  else "Reset"        if chng
                  else "Reset Armed" ))

    def events( self, since=None, purge=False ):
        """ Generator yields all events for all attributes. """
        for a in ( self._auto, self._start, self._running, self._fault, self._estop, self._reset ):
            for e in a.events( since=since, purge=purge ):
                yield e

    @property
    def online( self ):
        return self._auto._plc.online

    @property
    def auto( self ):
        value		= self._auto.value
        return None if value is None else bool( value )

    @property
    def running( self ):
        value		= self._running.value
        return None if value is None else bool( value )

    @property
    def fault( self ):
        """The Fault Status is negative logic; invert the actual value"""
        value		= self._fault.value
        return None if value is None else not bool( value )

    @property
    def estop( self ):
        """The E-Stop Status is positive logic (PLC converts it from Negative); invert the actual value"""
        value		= self._estop.value
        return None if value is None else bool( value )

    @property
    def reset( self ):
        value		= self._reset.value
        return None if value is None else bool( value )
    @reset.setter
    def reset( self, value ):
        if isinstance( value,  type_str_base ):
            value	= json.loads( value.lower() )
        self._reset.value = bool( value )

    @property
    def start( self ):
        value		= self._start.value
        return None if value is None else bool( value )
    @start.setter
    def start( self, value ):
        if isinstance( value,  type_str_base ):
            value	= json.loads( value.lower() )
        self._start.value = bool( value )

    @property
    def status( self ):
        if not self.online:
            return "offline"
        if self.fault:
            return "fault"
        running		= self.running
        auto		= self.auto
        start		= self.start
        if auto and not start and running:
            return "stopping"
        elif auto and start and not running:
            return "starting"
        # Manual mode, or start/running consistent
        return "started" if running else "stopped"


class motor_simulator( motor ):
    """
    Respond to value changes from the underlying PLC, and supply pseudo-random state change values.
    """
    def __init__( self, *args, **kwargs ):
        super( motor_simulator, self ).__init__( *args, **kwargs )
        try:
            self._auto._plc.write( self._auto._address, True )
            self.reset			= True
        except:
            # PLC not yet online; no worries.
            pass

    @property
    def status( self ):
        # 1/1000 Very occasionally take PLC offline, but 1/.1% back online quickly
        if self.online:
            if random.random() < .0001:
                self._auto._plc.online = False
                log.info( "%s: PLC offline" % ( self.identity ))
        else:
            if random.random() < .001:
                self._auto._plc.online = True
                log.info( "%s: PLC online" % ( self.identity ))

        try:
            # 1/1000 Very occasionally trigger an E-Stop (will affect several motors)
            if random.random() < ( .001 if self.estop else .0001 ):
                self._estop._plc.write( self._estop._address, not self.estop ) # invert

            # .01% Switch between Auto to Manual; .1 Switch from Manual to Auto
            if random.random() < ( .0001 if self.auto else 0.001 ):
                self._auto._plc.write( self._auto._address, not self.auto )
                log.info( "%5s: auto %s" % ( self.identity, self.auto ))

            # Fault or ! Auto; Stop.  Reset or ! Auto; Clear Fault and Reset
            if self.start and ( self.fault or self.estop or not self.auto ):
                self._start._plc.write( self._start._address, False )
            if self.fault and ( self.reset or not self.auto ):
                self._fault._plc.write( self._fault._address, True )	# -'ve logic
                self.reset 		= False
            if not self.auto:
                return super( motor_simulator, self ).status
                
            # .1% In Auto, toggle start/stop
            if random.random() < .001:
                self._start._plc.write( self._start._address, not self.start )
                log.info( "%s: start %s" % ( self.identity, self.start ))

            # 10% Bring running into alignment with start; 2% Fault on start, 1% on stop
            if self.start and not self.running:
                if not self.fault and random.random() < .10:
                    self._running._plc.write( self._running._address, True )
                    log.info( "%s: running %s" % ( self.identity, self.running ))
                elif random.random() < .02:
                    self._fault._plc.write( self._fault._address, False )# -'ve logic
            elif not self.start and self.running:
                if not self.fault and random.random() < .10:
                    self._running._plc.write( self._running._address, False )
                    log.info( "%s: running %s" % ( self.identity, self.running ))
                elif random.random() < .01:
                    self._fault._plc.write( self._fault._address, False )# -'ve logic

            # .5% Reset a fault
            if self.fault and random.random < .005:
                self._reset._plc.write( self._reset._address, True )
        except Exception as exc:
            log.warning( "motor simulator failure: %s" % ( str( exc )))

        return super( motor_simulator, self ).status
