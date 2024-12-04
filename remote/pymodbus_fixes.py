
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

from pymodbus import __version__ as pymodbus_version
from pymodbus.server import ModbusTcpServer, ModbusSerialServer
from pymodbus.client import ModbusTcpClient, ModbusSerialClient
from pymodbus.exceptions import ConnectionException
from pymodbus.pdu import ExceptionResponse
from pymodbus.datastore.store import ModbusSparseDataBlock


# Historically part of pymodbus to contain global defaults; now hosted here
@dataclass
class Defaults:
    Port	= 502
    UnitId	= 0
    Timeout	= 1.0


class modbus_communication_monitor( object ):
    """Outfit a pymodbus asyncio ModbusXxxServer to report communication_failed when a connect or
    listen is attempted, but does not succeed.  This is necessary in order to abort a ...Server if a
    connection is attempted but does not succeed (eg. a serial port doesn't exist or a network
    interface is invalid.)

    """
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
    """An asyncio.BaseProtocol based Modbus TCP server. """
    pass


class modbus_server_tcp_printing( modbus_server_tcp ):

    def callback_communication( self, established ):
        """Print the address successfully bound on self.transport; this is
        useful, if attempts are made to bind over a range of ports.  If the
        port is dynamic, we must use the socket.getsockname() result.

        The message printed to stdout must match the RE in server/network.py soak.

        """
        super( modbus_server_tcp_printing, self ).callback_communication( established )
        if established:
            self.server_address	= self.server.transport.sockets[0].getsockname()
            print( "Success; Started Modbus/TCP Simulator; PID = %d; address = %s:%s" % (
                os.getpid(), self.server_address[0], self.server_address[1] ))
            sys.stdout.flush()


class modbus_server_rtu( modbus_communication_monitor, ModbusSerialServer ):
    """An async Modbus Serial server.  Defaults to FramerType.RTU."""
    pass


class modbus_server_rtu_printing( modbus_server_rtu ):
    """Print the address successfully bound; a serial device in this case.

    The message printed to stdout must match the RE in server/network.py soak.

    """

    def callback_communication( self, established ):
        super( modbus_server_rtu_printing, self ).callback_communication( established )
        if established:
            print( "Success; Started Modbus/RTU Simulator; PID = %d; address = %s" % (
                os.getpid(), self.comm_params.source_address[0] ))
            sys.stdout.flush()


class modbus_client_timeout( object ):
    """Enforces a strict timeout on a complete transaction, including connection and I/O.  The
    beginning of a transaction is indicated by assigning a timeout to the .timeout property.  At
    any point, the remaining time available is computed by accessing the .timeout property.

    If .timeout is set to True/0, uses Defaults.Timeout around the entire transaction.  If
    transaction is never set or set to None, Defaults.Timeout is always applied to every I/O
    operation, independently (the original behaviour).

    Otherwise, the specified non-zero timeout is applied to the entire transaction.

    If a mutual exclusion lock on a <client> instance is desired (eg. if multiple Threads may be
    attempting to access this client simultaneously, eg. in the case where several independent
    Threads are accessing several slaves via multi-drop serial), it may be obtained using:

        with <client>:
            ...

    Note that such locks will *not* respond to any remaining transaction timeout!

    """
    def __init__( self, *args, **kwargs ):
        super( modbus_client_timeout, self ).__init__( *args, **kwargs )
        self._started	= None
        self._timeout	= None
        self._lock	= threading.Lock()

    @property
    def timeout( self ):
        """Returns the Defaults.Timeout, if no timeout = True|#.# (a hard timeout) has been specified."""
        if self._timeout in (None, True):
            logging.debug( "Transaction timeout default: %.3fs" % ( Defaults.Timeout ))
            return Defaults.Timeout
        now		= misc.timer()
        eta		= self._started + self._timeout
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
            self._started = None
            self._timeout = None
        else:
            self._started = misc.timer()
            self._timeout = ( Defaults.Timeout
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
    """A ModbusTcpClient with transaction timeouts and locking for Threaded connection sharing."""
    def __repr__( self ):
        return "<%s: %s>" % ( self, self.socket.__repr__() if self.socket else "closed" )


class modbus_client_rtu( modbus_client_timeout, ModbusSerialClient ):
    """A ModbusSerialClient with timeouts and locking for Threaded serial port sharing."""

    def __repr__( self ):
        return "<%s: %s>" % ( self, self.socket.__repr__() if self.socket else "closed" )
