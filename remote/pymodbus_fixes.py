
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
__copyright__                   = "Copyright (c) 2015 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

"""
remote.pymodbus_fixes -- PyModbus has some issues that need fixing.

Upgrade to pymodbus 3.
- No longer supports Python2
- Minimal shims to add locking for multi-Thread usage

"""
__all__				= [
    'modbus_server_tcp', 'modbus_server_tcp_printing',
    'modbus_server_rtu', 'modbus_server_rtu_printing',
    'modbus_client_timeout', 'modbus_client_rtu', 'modbus_client_tcp',
    'Defaults',
]

import asyncio
import errno
import logging
import os
import select
import serial
import socket
import sys
import threading
import traceback

from contextlib import suppress
from dataclasses import dataclass

try:
    from SocketServer import _eintr_retry
except ImportError:
    # Python < 2.7
    def _eintr_retry(func, *args):
        """restart a system call interrupted by EINTR"""
        while True:
            try:
                return func(*args)
            except (OSError, select.error) as e:
                if e.args[0] != errno.EINTR:
                    raise
from .. import misc
from ..server import network

from pymodbus.client import ModbusTcpClient, ModbusSerialClient
from pymodbus.datastore.store import ModbusSparseDataBlock
from pymodbus.framer import FramerType, FramerBase
from pymodbus.server import ModbusTcpServer, ModbusSerialServer


# Historically part of pymodbus to contain global defaults; now hosted here
@dataclass
class Defaults:
    Port	= 502
    UnitId	= 0
    Timeout	= 0.05


class modbus_communication_monitor( object ):
    """Outfit a pymodbus asyncio ModbusXxxServer to report communication_failed when a connect or
    listen is attempted, but does not succeed.  This is necessary in order to abort a ...Server if a
    connection is attempted but does not succeed (eg. a serial port doesn't exist or a network
    interface is invalid.)

    """
    def __init__(
            self,
            *args,
            framer: FramerType | type[FramerBase],
             **kwds ):
        """Allow custom framer classes by instantiating with a FramerType Enum value, and
        substituting the supplied Framer class after instantiation.  The framer may be an int or str
        (something convertible to a FramerType Enum), but if it's a FramerBase class, 

        """
        if not isinstance(framer, type) or not issubclass(framer, FramerBase):
            super( modbus_communication_monitor, self ).__init__( *args, framer=framer, **kwds )
        else:
            super( modbus_communication_monitor, self ).__init__( *args, framer=FramerType.RTU, **kwds )
            logging.warning( "Supplying alternate framer {framer!r}".format( framer=framer ))
            self.framer = framer

    async def connect( self ) -> bool:
        logging.warning( "Connect to {comm_name}...".format(
            comm_name	= self.comm_params.comm_name,
        ))
        connected		= await super( modbus_communication_monitor, self ).connect()
        self.callback_communication( established=connected )
        return connected

    async def listen( self ) -> bool:
        logging.warning( "Listen on {comm_name}...".format(
            comm_name	= self.comm_params.comm_name,
        ))
        listening		= await super( modbus_communication_monitor, self ).listen()
        self.callback_communication( established=listening )
        return listening

    def callback_communication( self, established ):
        if established:
            logging.normal( "Communication established on {comm_name}".format(
                comm_name	= self.comm_params.comm_name,
            ))
        else:
            logging.warning( "Communication attempt on {comm_name} failed".format(
                comm_name	= self.comm_params.comm_name,
            ))
            self.stop()

    def stop( self, loop=None ):
        if loop is None:
            loop		= asyncio.get_event_loop()
        logging.warning("Shutting down...".format( loop=loop ))
        asyncio.run_coroutine_threadsafe( self.shutdown(), loop )


class modbus_server_tcp( modbus_communication_monitor, ModbusTcpServer ):
    """An asyncio.BaseProtocol based Modbus TCP server.  This is an async server program, and must
    be run in an asyncio loop.

    """
    pass


class modbus_server_tcp_printing( modbus_server_tcp ):

    def callback_communication( self, established ):
        """Print the address successfully bound on self.transport; this is
        useful, if attempts are made to bind over a range of ports.  If the
        port is dynamic, we must use the socket.getsockname() result.

        The message printed to stdout must match the RE in server/network.py soak.

        IPv6 addresses must be formatted correctly for unambiguous parsing of port.

        """
        super( modbus_server_tcp_printing, self ).callback_communication( established )
        if established:
            for addr in self.transport.sockets:
                address		= (
                    "[{}]:{}"
                    if addr.family == socket.AF_INET6 else
                    "{}:{}"
                ).format( *addr.getsockname() )
                print( "Success; Started Modbus/TCP Simulator; PID = {pid}; address = {address}".format(
                    pid=os.getpid(), address=address ))
            sys.stdout.flush()


class modbus_server_rtu( modbus_communication_monitor, ModbusSerialServer ):
    """An async Modbus Serial server.  Defaults to FramerType.RTU.  This is an async server program,
    and must be run in an asyncio loop.

    """
    pass


class modbus_server_rtu_printing( modbus_server_rtu ):
    """Print the address successfully bound; a serial device in this case.

    The message printed to stdout must match the RE in server/network.py soak.

    """

    def callback_communication( self, established ):
        super( modbus_server_rtu_printing, self ).callback_communication( established )
        if established:
            print( "Success; Started Modbus/RTU Simulator; PID = {pid}; address = {address}".format(
                pid=os.getpid(), address=self.comm_params.source_address[0] ))
            sys.stdout.flush()


class modbus_client_timeout( object ):
    """Enforces a strict timeout on a complete transaction, including connection and I/O.  The
    beginning of a transaction is indicated by assigning a timeout to the .timeout property.  At
    any point, the remaining time available is computed by accessing the .timeout property.

    If a mutual exclusion lock on a <client> instance is desired (eg. if multiple Threads may be
    attempting to access this client simultaneously, eg. in the case where several independent
    Threads are accessing several slaves via multi-drop serial), it may be obtained using:

        with <client>:
            ...

    Note that such locks will *not* respond to any remaining transaction timeout!

    TODO:

    If .timeout is set to True/0, uses Defaults.Timeout around the entire transaction.  If
    transaction is never set or set to None, Defaults.Timeout is always applied to every I/O
    operation, independently (the original behaviour).

    Otherwise, the specified non-zero timeout is applied to the entire transaction.

    """
    def __init__( self, *args, **kwargs ):
        super( modbus_client_timeout, self ).__init__( *args, **kwargs )
        self._started		= None
        self._timeout		= None
        self._lock		= threading.Lock()

    @property
    def timeout( self ):
        """Returns the Defaults.Timeout, if no timeout = True|#.# (a hard timeout) has been specified."""
        if self._timeout in (None, True):
            logging.debug( "Transaction timeout default: %.3fs" % ( Defaults.Timeout ))
            return Defaults.Timeout
        now			= misc.timer()
        eta			= self._started + self._timeout
        if eta > now:
            logging.debug( "Transaction timeout remaining: %.3fs" % ( eta - now ))
            return eta - now
        logging.debug( "Transaction timeout expired" )
        return 0

    @timeout.setter
    def timeout( self, timeout ):
        """When a self.timeout = True|0|#.# is specified, initiate a hard timeout around the following
        transaction(s).  This means that any connect and/or read/write (_recv) must complete within
        the specified timeout (Defaults.Timeout, if 'True' or 0), starting *now*.  Reset to default
        behaviour with self.timeout = None.

        """
        if timeout is None:
            self._started	= None
            self._timeout	= None
        else:
            self._started	= misc.timer()
            self._timeout	= ( Defaults.Timeout
                                    if ( timeout is True or timeout == 0 )
                                    else timeout )

    def __enter__( self ):
        self._lock.acquire( True )
        logging.debug( "Acquired lock on %r", self )
        return self

    def __exit__( self, typ, val, tbk ):
        logging.debug( "Release  lock on %r", self )
        self._lock.release()
        return False


class modbus_client_tcp( modbus_client_timeout, ModbusTcpClient ):
    """A ModbusTcpClient with transaction timeouts and locking for Threaded connection sharing.
    These are synchronous clients, and run in the calling thread.

    """
    def __repr__( self ):
        return "<%s: %s>" % ( self, self.socket.__repr__() if self.socket else "closed" )


class modbus_client_rtu( modbus_client_timeout, ModbusSerialClient ):
    """A ModbusSerialClient with timeouts and locking for Threaded serial port sharing.  These are
    synchronous clients, and run in the calling thread.

    Attempts to establish platform serial "low_latency_mode" if available.

    """
    def __repr__( self ):
        return "<%s: %s>" % ( self, self.socket.__repr__() if self.socket else "closed" )

    def symbol_timing( self ) -> tuple[int,int]:
        """Calculate total bits and baud rate.  Compute elapsed I/O time per symbol in seconds ==
        bits_sym / baudrate.

        """
        assert self.socket is not None
        startbits		= 1
        bytesize		= self.socket.bytesize
        parity			= 1 if self.socket.parity is not serial.PARITY_NONE else 0
        stopbits		= self.socket.stopbits

        bits_per_symbol		= startbits + bytesize + parity + stopbits

        return bits_per_symbol, self.socket.baudrate

    def connect( self ) -> bool:
        """Set ASYNC_LOW_LATENCY to reduce USB<->UART kernel latency."""
        wasconnected		= self.connected
        nowconnected		= super( modbus_client_rtu, self ).connect()
        if nowconnected and not wasconnected:
            try:
                self.socket.set_low_latency_mode( True )
            except ( AttributeError, NotImplementedError, ValueError ) as exc:
                logging.debug( "Failed to low latency mode for %r: %s", self, exc )
            else:
                logging.debug( "Set serial port low latency mode for %r", self )

            # Compute the symbol timings for this serial connection
            bits_sym,baudrate	= self.symbol_timing()
            secs_sym		= float( bits_sym ) / baudrate

            self._t0		= secs_sym
            self.socket.inter_byte_timeout = self.inter_byte_timeout = 1.5 * self._t0
            self.silent_interval = max( 1.75/1000, 3.5 * self._t0 )  # min is ~=~ 19200 baud
            self._recv_interval = self.silent_interval  # ~=~ every 4 symbols
            logging.info( f"Serial {bits_sym:2}-bit symbol: {secs_sym*1000:10,.3f}ms/symbol @ {baudrate:,} baud == {1/secs_sym:,.3f}/s" )
            logging.info( f" Inter-byte timeout:  {self.inter_byte_timeout*1000:10,.3f}ms" )
            logging.info( f" Recv interval:       {self._recv_interval*1000:10,.3f}ms waiting for more data" )
            logging.info( f" Silent interval:     {self.silent_interval*1000:10,.3f}ms after sending" )
            logging.info( f" Response timeout:    {self.socket.timeout*1000:10,.3f}ms after sending" )
        return nowconnected
