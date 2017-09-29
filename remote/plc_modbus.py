
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
remote.plc_modbus -- Modbus PLC polling, reading and writing infrastructure
"""
__all__				= ['shatter', 'merge', 'poller_modbus']

import logging
import threading
import time
import traceback

from .. import misc
from .pymodbus_fixes import modbus_client_timeout, modbus_client_tcp
from .plc import poller, PlcOffline

from pymodbus.constants import Defaults
from pymodbus.exceptions import ModbusException, ParameterException
from pymodbus.bit_read_message import ReadDiscreteInputsRequest, ReadCoilsRequest
from pymodbus.bit_write_message import WriteSingleCoilRequest, WriteMultipleCoilsRequest
from pymodbus.register_read_message import ReadHoldingRegistersRequest, ReadInputRegistersRequest
from pymodbus.register_write_message import WriteSingleRegisterRequest, WriteMultipleRegistersRequest
from pymodbus.pdu import ExceptionResponse, ModbusResponse

log				= logging.getLogger( __package__ )

def shatter( address, count, limit=None ):
    """ Yields (address, count) ranges of length 'limit' sufficient to cover the
    given range.  If no limit, we'll deduce some appropriate limits for the
    deduced register type, appropriate for either multi-register reads or
    writes. """
    if not limit:
        if (        1 <= address <= 9999
            or  10001 <= address <= 19999
            or 100001 <= address <= 165536 ):
            # Coil read/write or Status read.
            limit	= 1968
        else:
            # Other type of register read/write (eg. Input, Holding)
            limit	= 123

    while count:
        taken		= min( count, limit or count )
        yield (address,taken)
        address	       += taken
        count	       -= taken


def merge( ranges, reach=1, limit=None ):
    """ Yields a series of independent register ranges: [(address, count), ...]
    from the provided ranges, merging any within 'reach' of each-other, with
    maximum range length 'limit'.  Will not attempt to merge addresses across a
    10000 boundary (to avoid merging different register types). """
    input		= iter( sorted( ranges ))

    base, length	= next( input )
    for address, count in input:
        if length:
            if ( address // 10000 == base // 10000
                 and address < base + length + ( reach or 1 )):
                log.debug( "Merging:  %10r + %10r == %r" % (
                        (base,length), (address,count), (base,address+count-base)))
                length	= address + count - base
                continue
            log.debug( "Unmerged: %10r + %10r w/reach %r" % (
                    (base,length), (address,count), reach))
            # We've been building a (base, length) merge range, but this
            # (address, count) doesn't merge; yield what we have
            for r in shatter( base, length, limit=limit ):
                log.debug( "Emitting: %10r==>%10r w/limit %r" % ((base,length), r, limit ))
                yield r
        # ... and, continue from this new range
        base, length	= address, count
    # Finally, clean up whatever range we were building (if any)
    for r in shatter( base, length, limit=limit ):
        log.debug( "Emitting: %10r==>%10r w/limit %r" % ((base,length), r, limit))
        yield r


class poller_modbus( poller, threading.Thread ):
    """A PLC object that communicates with a physical PLC via Modbus/{TCP,RTU} protocol, using the
    provided modbus_client_{tcp,rtu} instance.  Schedules polls of various registers at various
    poll rates, prioritizing the polls by age.

    Writes are transmitted at the earliest opportunity, and are synchronous (ie. do not return 'til
    the write is complete, or the plc is already offline).

    The first completely failed poll (no successful PLC I/O transactions) marks the PLC as offline,
    and it stays offline 'til a poll again succeeds.

    Only a single PLC I/O transaction is allowed to execute on the client, with self.client:...

    A 'unit' ID value may be provided; if not, Defaults.UnitId will be used.  This is normally 0x00
    (broadcast?), so it inappropriate for multi-drop slaves (eg. RS485).  The supplied default
    'unit' will be passed to all read/write requests (unless a 'unit' keyword is supplied to write
    request).  Since all 'read' requests are actually returning the results of the last polled
    value, all underlying polling _reads use the supplied 'unit' value.

    Maintains the prior ( ..., host="hostname", port=12345, ...) API, creating a Modbus/TCP client
    connection by default.  However, it is now possible to explicitly supply either a
    modbus_client_{tcp,rtu} instance using client=...

    """
    def __init__( self, description, client=None, reach=100, multi=False, unit=None,
                  host=None, port=None, **kwargs ):
        poller.__init__( self, description=description, **kwargs )
        threading.Thread.__init__( self, target=self._poller )
        if client is None:
            client		= modbus_client_tcp( host=host, port=port )
        else:
            assert host is None and port is None, "Must specify client or host/port; not both"
        assert isinstance( client, modbus_client_timeout ), \
            "Must provide a modbus_client_{tcp,rtu}, not: %r" % client
        self.client		= client
        self.unit		= Defaults.UnitId if unit is None else unit
        self.daemon		= True
        self.done		= False
        self.reach		= reach		# Merge registers this close into ranges
        self.multi		= multi		# Force WriteMultipleRegisters... even for single registers
        self.polling		= set()		# Ranges known to be successfully polling
        self.failing		= set() 	# Ranges known to be failing
        self.duration		= 0.0		# Duration of last poll completed
        self.counter		= 0		# Total polls performed
        self.load		= None,None,None# total poll durations over last ~1, 5 and 15 min
        self.start()

    def stop( self ):
        self.done		= True

    def join( self, timeout=None ):
        if self.is_alive():
            log.info( "Joining: %s", self.description )
        self.stop()
        super( poller_modbus, self ).join( timeout=timeout )

    def _poller( self, *args, **kwargs ):
        """ Asynchronously (ie. in another thread) poll all the specified
        registers, on the designated poll cycle.  Until we have something to do
        (self.rate isn't None), just wait.

        We'll log whenever we begin/cease polling any given range of registers.
        """
        log.info( "Poller starts: %r, %r ", args, kwargs )
        target			= misc.timer()
        while not self.done and logging:	# Module may be gone in shutting down
            # Poller is dormant 'til a non-None/zero rate and data specified
            if not self.rate or not self._data:
                time.sleep( .1 )
                continue

            # Delay 'til poll target
            now			= misc.timer()
            if now < target:
                time.sleep( target - now )
                now		= misc.timer()

            # Ready for another poll.  Check if we've slipped (missed cycle(s)), and then compute
            # the next poll cycle target; this attempts to retain cadence.
            slipped		= int( ( now - target ) / self.rate )
            if slipped:
                log.normal( "Polling: PLC %s slipped; missed %d cycles", self.description, slipped )
            target	       += self.rate * ( slipped + 1 )

            # Perform polls, re-acquiring lock between each poll to allow others
            # to interject.  We'll sort the known register addresses in _data,
            # merge ranges, read the values from the PLC, and store them in
            # _data.

            # TODO: Split on and optimize counts for differing multi-register
            # limits for Coils, Registers

            # WARN: list comprehension over self._data must be atomic, because
            # we don't lock, and someone could call read/poll, adding entries to
            # self._data between reads.  However, since merge's register ranges
            # are sorted, all self._data keys are consumed before the list is
            # iterated.
            rngs		= set( merge( ( (a,1) for a in self._data ), reach=self.reach ))
            succ		= set()
            fail		= set()
            busy		= 0.0 # time spent polling (excluding time blocked, ie. writes)
            for address, count in rngs:
                with self.client: # block 'til we can begin a transaction
                    begin	= misc.timer()
                    try:
                        # Read values; on success (no exception, something other
                        # than None returned), immediately take online;
                        # otherwise attempts to _store will be rejected.
                        value	= self._read( address, count, unit=self.unit )
                        if not self.online:
                            self.online = True
                            log.critical( "Polling: PLC %s online; success polling %s: %s",
                                    self.description, address, misc.reprlib.repr( value ))
                        if (address,count) not in self.polling:
                            log.detail( "Polling: PLC %s %6d-%-6d (%5d)", self.description,
                                        address, address+count-1, count )
                        succ.add( (address, count) )
                        self._store( address, value, create=False ) # Handle scalar or list/tuple value(s)
                    except ModbusException as exc:
                        # Modbus error; Couldn't read the given range.  Only log
                        # the first time failure to poll this range is detected
                        fail.add( (address, count) )
                        if (address, count) not in self.failing:
                            log.warning( "Failing: PLC %s %6d-%-6d (%5d): %s", self.description,
                                         address, address+count-1, count, str( exc ))
                    except Exception as exc:
                        # Something else; always log
                        fail.add( (address, count) )
                        log.warning( "Failing: PLC %s %6d-%-6d (%5d): %s", self.description,
                                address, address+count-1, count, traceback.format_exc() )
                    busy       += misc.timer() - begin

                # Prioritize other lockers (ie. write).  Contrary to popular opinion, sleep(0) does
                # *not* effectively yield the current Thread's quanta, at least on Python 2.7.6!
                time.sleep(0.001)

            # We've already warned about polls that have failed; also log all
            # polls that have ceased (failed, or been replaced by larger polls)
            ceasing		= self.polling - succ - fail
            for address, count in ceasing:
                log.info( "Ceasing: PLC %s %6d-%-6d (%5d)", self.description,
                          address, address+count-1, count )

            self.polling	= succ
            self.failing	= fail
            self.duration	= busy

            # The "load" is computed by comparing the "duration" of the last poll vs. the target
            # poll rate (in seconds).  A load of 1.0 indicates the polls consumed exactly 100% of
            # the target rate.  Compute loads over approximately the last 1, 5 and 15 minutes worth
            # of polls.  The load is the proportion of the current poll rate that is consumed by
            # poll activity.  Even if the load < 1.0, polls may "slip" due to other (eg. write)
            # activity using PLC I/O capacity.
            load		= ( busy / self.rate ) if self.rate > 0 else 1.0
            ppm			= ( 60.0 / self.rate ) if self.rate > 0 else 1.0
            self.load		= tuple(
                misc.exponential_moving_average( cur, load, 1.0 / ( minutes * ppm ))
                for minutes,cur in zip((1, 5, 15), self.load ))

            # Finally, if we've got stuff to poll and we aren't polling anything successfully, and
            # we're not yet offline, warn and take offline, and then report the completion of another
            # poll cycle.
            if self._data and not succ and self.online:
                log.critical( "Polling: PLC %s offline", self.description )
                self.online	= False
            self.counter       += 1

    def write( self, address, value, **kwargs ):
        with self.client: # block 'til we can begin a transaction
            super( poller_modbus, self ).write( address, value, **kwargs )

    def _write( self, address, value, **kwargs ):
        """Perform the write, enforcing Defaults.Timeout around the entire transaction.  Normally
        returns None, but may raise a ModbusException or a PlcOffline if there are communications
        problems.

        Use a supplied 'unit' ID, or the one specified/deduced at construction.

        """
        self.client.timeout 	= True

        if not self.client.connect():
            raise PlcOffline( "Modbus Write to PLC %s/%6d failed: Offline; Connect failure" % (
                    self.description, address ))

        # Use address to deduce Holding Register or Coil (the only writable
        # entities); Statuses and Input Registers result in a pymodbus
        # ParameterException
        multi			= hasattr( value, '__iter__' )
        writer			= None
        if 400001 <= address <= 465536:
            # 400001-465536: Holding Registers
            writer		= ( WriteMultipleRegistersRequest if multi or self.multi
                                    else WriteSingleRegisterRequest )
            address    	       -= 400001
        elif 40001 <= address <= 99999:
            #  40001-99999: Holding Registers
            writer		= ( WriteMultipleRegistersRequest if multi or self.multi
                                    else WriteSingleRegisterRequest )
            address    	       -= 40001
        elif 1 <= address <= 9999:
            #      1-9999: Coils
            writer		= ( WriteMultipleCoilsRequest if multi # *don't* force multi
                                    else WriteSingleCoilRequest )
            address	       -= 1
        else:
            # 100001-165536: Statuses (not writable)
            # 300001-365536: Input Registers (not writable)
            # 10001-19999: Statuses (not writable)
            # 30001-39999: Input Registers (not writable)
            pass
        if not writer:
            raise ParameterException( "Invalid Modbus address for write: %d" % ( address ))

        if writer is WriteMultipleRegistersRequest:
            # Overcome bug in 1.2.0/1.3.0 in handling single requests.  Also reifies generators.
            value		= list( value ) if multi else [ value ]

        unit			= kwargs.pop( 'unit', self.unit )
        result			= self.client.execute( writer( address, value, unit=unit, **kwargs ))
        if isinstance( result, ExceptionResponse ):
            raise ModbusException( str( result ))
        assert isinstance( result, ModbusResponse ), "Unexpected non-ModbusResponse: %r" % result

    def _read( self, address, count=1, **kwargs ):
        """Perform the read, enforcing Defaults.Timeout around the entire transaction.  Returns the
        result bit(s)/register(s), or raises an Exception; probably a ModbusException or a
        PlcOffline for communications errors, but could be some other type of Exception.

        Use a supplied 'unit' ID, or the one specified/deduced at construction.

        """
        self.client.timeout 	= True

        if not self.client.connect():
            raise PlcOffline( "Modbus Read  of PLC %s/%6d failed: Offline; Connect failure" % (
                    self.description, address ))

        # Use address to deduce Holding/Input Register or Coil/Status.
        reader			= None
        xformed			= address
        if 400001 <= address <= 465536:
            reader		= ReadHoldingRegistersRequest
            xformed	       -= 400001
        elif 300001 <= address <= 365536:
            reader		= ReadInputRegistersRequest
            xformed    	       -= 300001
        elif 100001 <= address <= 165536:
            reader		= ReadDiscreteInputsRequest
            xformed    	       -= 100001
        elif 40001 <= address <= 99999:
            reader		= ReadHoldingRegistersRequest
            xformed    	       -= 40001
        elif 30001 <= address <= 39999:
            reader		= ReadInputRegistersRequest
            xformed    	       -= 30001
        elif 10001 <= address <= 19999:
            reader		= ReadDiscreteInputsRequest
            xformed    	       -= 10001
        elif 1 <= address <= 9999:
            reader		= ReadCoilsRequest
            xformed	       -= 1
        else:
            # Invalid address
            pass
        if not reader:
            raise ParameterException( "Invalid Modbus address for read: %d" % ( address ))

        unit			= kwargs.pop( 'unit', self.unit )
        request			= reader( xformed, count, unit=unit, **kwargs )
        log.debug( "%s/%6d-%6d transformed to %s", self.description, address, address + count - 1,
                   request )

        result 			= self.client.execute( request )
        if isinstance( result, ExceptionResponse ):
            # The remote PLC returned a response indicating it encountered an
            # error processing the request.  Convert it to raise a ModbusException.
            raise ModbusException( str( result ))
        assert isinstance( result, ModbusResponse ), "Unexpected non-ModbusResponse: %r" % result

        # The result may contain .bits or .registers,  1 or more values
        values			= result.bits if hasattr( result, 'bits' ) else result.registers
        return values if len( values ) > 1 else values[0]

