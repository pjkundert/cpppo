
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
remote.plc	-- basic PLC polling infrastructure
"""
__all__				= ['PlcOffline', 'poller', 'poller_simulator']

import collections
import logging

from .. import misc

log				= logging.getLogger( __package__ )


class PlcOffline( Exception ):
    pass

class poller( object ):
    """A PLC communications object that knows how to read/write addresses.  Just
    remembers what it is told (defaults to None).  When not online, all read
    accesses return None, all write access raise exception.

      .offline		-- True iff PLC is offline
      .poll		-- arrange for an address to be polled at a rate
      .read		-- Read an address from the cache; None if offline
      .write		-- Write an address, blocks 'til complete; raise if offline/fails

    Protected methods.  Override these to interface to an actual device;
    setting/clearing self.online on failure.  The default implementation
    simulates latency, losing any values written but not "polled" before going
    online.

      ._write		-- Perform a write of a data value to device
      ._cache		-- Store a data value
      ._receive		-- Get a data value

    """
    def __init__( self, description=None, rate=None ):
        self.description	= id( self ) if description is None else description
        self.online		= True
        self.rate		= rate
        self._data		= {}

    def poll( self, address, rate=None ):
        """ Remembers the minimum requested rate, and prepares to poll; ensure someone has specified a rate!"""
        if rate is not None:
            self.rate 		= min( self.rate or rate, rate )
        self._poll( address )

    def read( self, address ):
        """ Establishes polling on the given address, receives incoming values,
        returning the latest known value, or None if offline. """
        self._poll( address )
        self._receive()
        value			= self._data[address] if self.online else None
        if log.isEnabledFor( logging.DEBUG ):
            log.debug( "%s/%6d %s> %s", self.description, address, "-x" if not self.online else "--",
                       misc.reprlib.repr( value ))
        return value

    def write( self, address, value, **kwargs ):
        """ Writes the value; if the PLC is online, logs at a relatively aggressive level."""
        count			= 1 if not hasattr( value, '__len__' ) else len( value )
        ( log.detail if self.online else log.normal )( "%s/%6d <%s (%3d) %s" % (
            self.description, address, "x=" if not self.online else "==",
            count, misc.reprlib.repr( value )))
        if not self.online:
            raise PlcOffline( "Write to PLC %s/%6dd failed: Offline" % ( self.description, address ))
        self._write( address, value, **kwargs )

    # Protected methods
    def _poll( self, address ):
        """ Prepare to actually poll address """
        self._data.setdefault( address, None )

    def _write( self, address, value, **kwargs ):
        """ Write a value at an address to an underlying device; by default,
        store it locally. """
        self._store( address, value )

    def _store( self, address, value, create=True ):
        """Remember data value(s) received; by default, just store it/them in or _data table.  Any value
        stored while offline is lost (this will only occur under simulated PLCs, of course)!  Logs
        at only high logging levels, due to large amounts of output (eg. due to polling).

        If 'create' is False, we will not create entries new to store data; an entry must already
        exist.  This is useful, for example, when reading bit data (Coils, Input Statuses), which
        may return more data than you requested, causing an expansion in the subsequent polls.

        """
        if not hasattr( value, '__getitem__' ):
            value		= [ value ]
        log.detail( "%s/%6d %s> (%3d) %s",
                self.description, address, "-x" if not self.online else "--",
                    len( value ), misc.reprlib.repr( value ))
        if self.online:
            for offset in range( len( value )):
                if create or address+offset in self._data:
                    self._data[address+offset] = value[offset]

    def _receive( self ):
        """ Receive incoming data. """
        pass

    def _read( self, address ):
        """ Read a value at an address from an underlying device. """
        raise Exception( "Not Implemented" )


class poller_simulator( poller ):
    """
    Simulates delayed polling of any data written to a simulated PLC.  Each
    value written is stored in _cache with the time it was written.  Later, the
    values are received and stored at a simulated poll rate.
    """
    def __init__( self, description, **kwargs ):
        super( poller_simulator, self ).__init__( description=description, **kwargs )
        self._cache		= {}		# times/values stored to simulated PLC
        self._polled		= misc.timer()	#   scheduled to be polled

    def _poll( self, address ):
        """ Simulates an initial value of 0 for every new address """
        if address not in self._data:
            self._write( address, 0 )
        super( poller_simulator, self )._poll( address )

    def _write( self, address, value ):
        """ Remember a data value, with a timer to simulate delayed polling """
        self._cache.setdefault( address, collections.deque() ).append( (misc.timer(), value) )

    def _receive( self ):
        """ Receive any previously cached data, with a latency of roughly 1/2
        the specified polling rate"""
        now			= misc.timer()
        if self._polled + self.rate > now:
            return
        log.debug( "%s polled" % ( self.description ))
        self._polled       	+= self.rate
        for address, vlist in self._cache.items():
            while vlist:
                t, value	= vlist[0]
                if t > self._polled:
                    break
                # When offline, any value other than the last one written to the
                # PLC is lost; _store will discard if offline, logging with -x>
                # indicates that we'll never see it.
                if self.online or len( vlist ) > 1:
                    self._store( address, value )
                if not self.online:
                    break
                vlist.popleft()
