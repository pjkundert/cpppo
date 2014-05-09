
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
from __future__ import division

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

"""
remote.plc_modbus -- Modbus/TCP PLC polling, reading and writing infrastructure
"""
__all__				= ['ModbusTcpClientTimeout', 'ModbusTcpServerActions', 'poller_modbus']

import logging
import select
import socket
import sys
import threading
import time
import traceback

import cpppo
from   cpppo.server import network
from   cpppo.remote.plc import poller, PlcOffline

# We need to monkeypatch ModbusTcpServer's SocketServer.serve_forever to be
# Python3 socketserver compatible.  When pymodbus is ported to Python3, this
# will not be necessary in the Python3 implementation.
assert sys.version_info.major < 3, "pymodbus is not yet Python3 compatible"
from pymodbus.server.sync import ModbusTcpServer
from SocketServer import _eintr_retry

from pymodbus.constants import Defaults
from pymodbus.client.sync import ModbusTcpClient
from pymodbus.exceptions import *
from pymodbus.bit_read_message import *
from pymodbus.bit_write_message import *
from pymodbus.register_read_message import *
from pymodbus.register_write_message import *
from pymodbus.pdu import (ExceptionResponse, ModbusResponse)
from pymodbus.server.sync import ModbusConnectedRequestHandler

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )

log				= logging.getLogger( __package__ )

class ModbusTcpServerActions( ModbusTcpServer ):
    """Augments the stock pymodbus ModbusTcpServer with the Python3 'socketserver'
    class periodic invocation of the .service_actions() method from within the
    main serve_forever loop.  This allows us to perform periodic service:

        class our_modbus_server( ModbusTcpServerActions ):
            def service_actions( self ):
                logging.info( "Doing something every ~<seconds>" )


        # Start our modbus server, which spawns threads for each new client
        # accepted, and invokes service_actions every ~<seconds> in between.
        modbus = ModbusTcpServerActions()
        modbus.serve_forever( poll_interval=<seconds> )


    The serve_forever implementation comes straight from Python3 socketserver,
    which is basically an enhancement of Python2 SocketServer.

    """
    def serve_forever( self, poll_interval=.5 ):
        self._BaseServer__is_shut_down.clear()
        try:
            while not self._BaseServer__shutdown_request:
                r, w, e = _eintr_retry( select.select, [self], [], [], poll_interval )
                if self in r:
                    self._handle_request_noblock()

                self.service_actions()  # <<< Python3 socketserver added this
        finally:
            self._BaseServer__shutdown_request = False
            self._BaseServer__is_shut_down.set()

    def service_actions( self ):
        """Override this to receive service every ~poll_interval s."""
        pass

class ModbusTcpClientTimeout( ModbusTcpClient ):
    """Enforces a strict timeout on a complete transaction, including connection and I/O.  The
    beginning of a transaction is indicated by assigning a timeout to the transaction property.  At
    any point, the remaining time available is computed by accessing the transaction property.

    If .timeout is set to True/0, uses Defaults.Timeout around the entire transaction.  If
    transaction is never set or set to None, Defaults.Timeout is always applied to every I/O
    operation, independently (the original behaviour).
    
    Otherwise, the specified non-zero timeout is applied to the entire transaction.

    """
    def __init__( self, *args, **kwargs):
        super( ModbusTcpClientTimeout, self ).__init__( *args, **kwargs )
        self._started	= None
        self._timeout	= None

    @property
    def timeout( self ):
        """Returns the Defaults.Timeout, if no timeout = True|#.# (a hard timeout) has been specified."""
        if self._timeout in (None, True):
            log.debug( "Transaction timeout default: %.3fs" % ( Defaults.Timeout ))
            return Defaults.Timeout
        now		= cpppo.timer()
        eta		= self._started + self._timeout
        if eta > now:
            log.debug( "Transaction timeout remaining: %.3fs" % ( eta - now ))
            return eta - now
        log.debug( "Transaction timeout expired" )
        return 0
    @timeout.setter
    def timeout( self, timeout ):
        """When a self.timeout = True|0|#.# is specified, initiate a hard timeout around the following
        transaction(s).  This means that any connect and/or read/write (_recv) must complete within
        the specified timeout (Defaults.Timeout, if 'True' or 0), starting *now*.  Reset to default
        behaviour with self.timeout = None.

        """
        if timeout is None:
            self._started = None
            self._timeout = None
        else:
            self._started = cpppo.timer()
            self._timeout = ( Defaults.Timeout 
                              if ( timeout is True or timeout == 0 )
                              else timeout )

    def connect(self):
        """Duplicate the functionality of connect (handling optional .source_address attribute added
        in pymodbus 1.2.0), but pass the computed remaining timeout.

        """
        if self.socket: return True
        log.debug( "Connecting to (%s, %s)" % ( self.host, self.port ))
        begun			= cpppo.timer()
        timeout			= self.timeout # This computes the remaining timeout available
        try:
            self.socket		= socket.create_connection( (self.host, self.port),
                                    timeout=timeout, source_address=getattr( self, 'source_address', None ))
        except socket.error as exc:
            log.debug('Connection to (%s, %s) failed: %s' % (
                self.host, self.port, exc ))
            self.close()
        finally:
            log.debug( "Connect completed in %.3fs" % ( cpppo.timer() - begun ))

        return self.socket != None

    def _recv( self, size ):
        """On a receive timeout, closes the socket and raises a ConnectionException.  Otherwise,
        returns the available input"""
        if not self.socket:
            raise ConnectionException( self.__str_() )
        begun			= cpppo.timer()
        timeout			= self.timeout # This computes the remaining timeout available

        r, w, e			= select.select( [self.socket], [], [], timeout )
        if r:
            result		= super( ModbusTcpClientTimeout, self )._recv( size )
            log.debug( "Receive success in %7.3f/%7.3fs" % ( cpppo.timer() - begun, timeout ) )
            return result

        self.close()
        log.debug( "Receive failure in %7.3f/%7.3fs" % ( cpppo.timer() - begun, timeout ) )
        raise ConnectionException("Receive from (%s, %s) failed: Timeout" % (
                self.host, self.port ))


class ModbusTcpRequestHandler( ModbusConnectedRequestHandler ):
    '''Implements the modbus server protocol for a TCP/IP client, with the SocketServer.BaseRequest
    interface, and with specified latency between checking for self.running, and the specified drain
    delay.  The default latency (.1s) should not consume too much CPU while providing fairly prompt
    Thread termination, and drain (.1s) is probably appropriate for a LAN situation on a lightly
    loaded server.

    Since the constructor is limited to exactly the 3 parameters (because it is created in code that
    we cannot alter), you must derive a new class with different values:

        class my_handler( ModbusTcpRequestHandler ):
            drain = 1.0

    '''
    latency			= .1
    drain			= .1
    def __init__( self, request, client, server ):
        ModbusConnectedRequestHandler.__init__( self, request, client, server )
        if self.latency is not None:
            assert self.latency > 0, "Cannot specify a zero latency polling timeout"

    def stop( self ):
        self.running		= False

    def join( self, timeout=None ):
        """Ensure a Thread is stopped, drained and closed in a timely fashion.  The timeouts to respond to
        stop() and for the Thread to drain and close the socket are specified with the Constructor's
        latency= and drain= keywords; if these are reliably implemented, it is not necessary to
        provide a timeout here.

        """
        self.stop()
        ModbusConnectedRequestHandler.join( self, timeout=timeout )

    def handle( self ):
        '''Callback when we receive any data, until self.running becomes not True.  Blocks indefinitely
        awaiting data.  If shutdown is required, then the global socket.settimeout(<seconds>) may be
        used, to allow timely checking of self.running.  However, since this also affects socket
        connects, if there are outgoing socket connections used in the same program, then these will
        be prevented, if the specfied timeout is too short.  Hence, this is unreliable.

        Specify a latency of None for no recv timeout, and a drain of 0 for no waiting for reply
        EOF, for same behavior as stock ModbusConnectedRequestHandler.

        NOTE: This loop is restructured to employ finally: for logging, but is functionally
        equivalent to the original.

        '''
        log.info("Modbus/TCP client socket handling started for %s", self.client_address )
        try:
            while self.running:
                data		= network.recv( self.request, timeout=self.latency )
                if data is None:
                    continue			# No data w'in timeout; just check self.running
                if not data:
                    self.running= False	# EOF (empty data); done
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(" ".join([hex(ord(x)) for x in data]))
                self.framer.processIncomingPacket( data, self.execute )
        except socket.error as exc:
            log.error("Modbus/TCP client socket error occurred %s", exc )
            self.running	= False
        except:
            log.error("Modbus/TCP client socket exception occurred %s", traceback.format_exc() )
            self.running	= False
        finally:
            log.info("Modbus/TCP client socket handling stopped for %s", self.client_address )

    def shutdown_request( self ):
        '''The default SocketServer.shutdown_request does send a shutdown(socket.SHUT_WR), but does NOT
        wait for the socket to drain before closing it, potentially leaving the kernel socket dirty
        (filled with unclaimed data; at least the client's EOF).  Drain the socket, then close it.
        Ignores ENOTCONN (and other) socket.error if socket is already closed.

        '''
        log.detail( "Modbus/TCP client socket shutdown/drain %s", self.client_address )
        network.drain( self.request, timeout=self.drain, close=False )
        self.close_request()

            
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
                log.debug( "Emitting: %10r==>%10r" % ((base,length), r ))
                yield r
        # ... and, continue from this new range
        base, length	= address, count
    # Finally, clean up whatever range we were building (if any)
    for r in shatter( base, length, limit=limit ):
        log.debug( "Emitting: %10r==>%10r w/limit %r" % ((base,length), r, limit))
        yield r


class poller_modbus( poller, threading.Thread ):
    """
    A PLC object that communicates with a physical PLC via Modbus/TCP protocol.  Schedules polls of
    various registers at various poll rates, prioritizing the polls by age.

    Writes are transmitted at the earliest opportunity, and are synchronous (ie. do not return 'til
    the write is complete, or the plc is already offline).
    
    The first completely failed poll (no successful PLC I/O transactions) marks
    the PLC as offline, and it stays offline 'til a poll again succeeds.

    Only a single PLC I/O transaction is allowed to execute on ModbusTcpClient*, with self.lock.
    """
    def __init__( self, description,
                  host='localhost', port=Defaults.Port, reach=100, daemon_threads=None, **kwargs ):
        poller.__init__( self, description=description, **kwargs )
        threading.Thread.__init__( self, target=self._main )
        self.client		= ModbusTcpClientTimeout( host=host, port=port )
        self.lock		= threading.Lock()
        if daemon_threads:
            self.daemon		= True
        self.done		= False
        self.reach		= reach		# Merge registers this close into ranges
        self.polling		= set()		# Ranges known to be successfully polling
        self.failing		= set() 	# Ranges known to be failing
        self.duration		= 0.0		# Duration of last poll completed
        self.counter		= 0		# Total polls performed
        self.load		= None,None,None# total poll durations over last ~1, 5 and 15 min
        self.start()

    def stop( self ):
        self.done		= True

    def join( self, timeout=None ):
        log.info( "Poller cleanup" )
        try:
            self.stop()
            super( poller_modbus, self ).join( timeout=timeout )
        finally:
            log.info( "Poller cleanup complete" )

    def _main( self ):
        """Execute the polling, ensuring the client connection is closed on completion."""
        log.detail( "Poller starting" )
        try:
            self._poller()
        finally:
            self.client.close() # safe if already closed
            log.detail( "Poller stopped" )

    def _poller( self ):
        """Asynchronously (ie. in another thread) poll all the specified registers, on the designated
        poll cycle.  Until we have something to do (self.rate isn't None), just wait.

        We'll log whenever we begin/cease polling any given range of registers.

        """
        target			= cpppo.timer()
        while not self.done and logging:	# Module may be gone in shutting down
            # Poller is dormant 'til a non-None/zero rate and data specified
            if not self.rate or not self._data:
                time.sleep( .1 )
                continue

            # Delay 'til poll target
            now			= cpppo.timer()
            if now < target:
                time.sleep( target - now )
                now		= cpppo.timer()

            # Ready for another poll.  Check if we've slipped (missed cycle(s)), and then compute
            # the next poll cycle target; this attempts to retain cadence.
            slipped		= int( ( now - target ) / self.rate )
            if slipped:
                log.normal( "Polling slipped; missed %d cycles" % ( slipped ))
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
            busy		= 0.0
            for address, count in rngs:
                with self.lock:
                    begin	= cpppo.timer()
                    try:
                        # Read values; on success (no exception, something other
                        # than None returned), immediately take online;
                        # otherwise attempts to _store will be rejected.
                        value	= self._read( address, count )
                        if not self.online:
                            self.online = True
                            log.critical( "Polling: PLC %s online; success polling %s: %s" % (
                                    self.description, address, cpppo.reprlib.repr( value )))
                        if (address,count) not in self.polling:
                            log.detail( "Polling %6d-%-6d (%5d)" % ( address, address+count-1, count ))
                        succ.add( (address, count) )
                        self._store( address, value ) # Handle scalar or list/tuple value(s)
                    except ModbusException as exc:
                        # Modbus error; Couldn't read the given range.  Only log
                        # the first time failure to poll this range is detected
                        fail.add( (address, count) )
                        if (address, count) not in self.failing:
                            log.warning( "Failing %6d-%-6d (%5d): %s" % (
                                    address, address+count-1, count, str( exc )))
                    except Exception as exc:
                        # Something else; always log
                        fail.add( (address, count) )
                        log.warning( "Failing %6d-%-6d (%5d): %s" % (
                                address, address+count-1, count, traceback.format_exc() ))
                    busy       += cpppo.timer() - begin

                # Prioritize other lockers (ie. write).  Contrary to popular opinion, sleep(0) does
                # *not* effectively yield the current Thread's quanta, at least on Python 2.7.6!
                time.sleep(0.001)

            # We've already warned about polls that have failed; also log all
            # polls that have ceased (failed, or been replaced by larger polls)
            ceasing		= self.polling - succ - fail
            for address, count in ceasing:
                log.info( "Ceasing %6d-%-6d (%5d)" % ( address, address+count-1, count ))

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
                cpppo.exponential_moving_average( cur, load, 1.0 / ( minutes * ppm ))
                for minutes,cur in zip((1, 5, 15), self.load ))

            # Finally, if we've got stuff to poll and we aren't polling anything successfully, and
            # we're not yet offline, warn and take offline, and then eport the completion of another
            # poll cycle.
            if self._data and not succ and self.online:
                log.critical( "Polling: PLC %s offline" % ( self.description ))
                self.online	= False
            self.counter       += 1


    def write( self, address, value, **kwargs ):
        with self.lock:
            super( poller_modbus, self ).write( address, value, **kwargs )

    def _write( self, address, value, **kwargs ):
        """Perform the write, enforcing Defaults.Timeout around the entire transaction.
        Normally returns None, but may raise a ModbusException or a PlcOffline
        if there are communications problems.

        """
        self.client.timeout 	= True

        if not self.client.connect():
            raise PlcOffline( "Modbus/TCP Write to PLC %s/%6d failed: Offline; Connect failure" % (
                    self.description, address ))

        # Use address to deduce Holding Register or Coil (the only writable
        # entities); Statuses and Input Registers result in a pymodbus
        # ParameterException
        multi			= isinstance( value, (list,tuple) )
        writer			= None
        if 400001 <= address <= 465536:
            # 400001-465536: Holding Registers
            writer		= ( WriteMultipleRegistersRequest 
                                    if multi else WriteSingleRegisterRequest )
            address    	       -= 400001
        elif 40001 <= address <= 99999:
            #  40001-99999: Holding Registers
            writer		= ( WriteMultipleRegistersRequest if multi 
                                    else WriteSingleRegisterRequest )
            address    	       -= 40001
        elif 1 <= address <= 9999:
            #      1-9999: Coils
            writer		= ( WriteMultipleCoilsRequest 
                                    if multi else WriteSingleCoilRequest )
            address	       -= 1
        else:
            # 100001-165536: Statuses (not writable)
            # 300001-365536: Input Registers (not writable)
            # 10001-19999: Statuses (not writable)
            # 30001-39999: Input Registers (not writable)
            pass
        if not writer:
            raise ParameterException( "Invalid Modbus address for write: %d" % ( address ))

        result			= self.client.execute( writer( address, value, **kwargs ))
        if isinstance( result, ExceptionResponse ):
            raise ModbusException( str( result ))
        assert isinstance( result, ModbusResponse ), "Unexpected non-ModbusResponse: %r" % result

    def _read( self, address, count=1, **kwargs ):
        """Perform the read, enforcing Defaults.Timeout around the entire transaction.
        Returns the result bit(s)/regsiter(s), or raises an Exception; probably
        a ModbusException or a PlcOffline for communications errors, but could
        be some other type of Exception.

        """
        self.client.timeout 	= True

        if not self.client.connect():
            raise PlcOffline( "Modbus/TCP Read  of PLC %s/%6d failed: Offline; Connect failure" % (
                    self.description, address ))
        
        # Use address to deduce Holding/Input Register or Coil/Status.
        reader			= None
        if 400001 <= address <= 465536:
            reader		= ReadHoldingRegisterRequest
            address    	       -= 400001
        elif 300001 <= address <= 365536:
            reader		= ReadInputRegisterRequest
            address    	       -= 300001
        elif 100001 <= address <= 165536:
            reader		= ReadDiscreteInputsRequest
            address    	       -= 100001
        elif 40001 <= address <= 99999:
            reader		= ReadHoldingRegistersRequest
            address    	       -= 40001
        elif 30001 <= address <= 39999:
            reader		= ReadInputRegisterRequest
            address    	       -= 30001
        elif 10001 <= address <= 19999:
            reader		= ReadDiscreteInputsRequest
            address    	       -= 10001
        elif 1 <= address <= 9999:
            reader		= ReadCoilsRequest
            address	       -= 1
        else:
            # Invalid address
            pass
        if not reader:
            raise ParameterException( "Invalid Modbus address for read: %d" % ( address ))

        result 			= self.client.execute( reader( address, count, **kwargs ))
        if isinstance( result, ExceptionResponse ):
            # The remote PLC returned a response indicating it encountered an
            # error processing the request.  Convert it to raise a ModbusException.
            raise ModbusException( str( result ))
        assert isinstance( result, ModbusResponse ), "Unexpected non-ModbusResponse: %r" % result

        # The result may contain .bits or .registers,  1 or more values
        values			= result.bits if hasattr( result, 'bits' ) else result.registers
        return values if len( values ) > 1 else values[0]

