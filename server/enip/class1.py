"""Cyclic, unicast EtherNet/IP Class 1 Input Only connections."""

from __future__ import absolute_import, division

import logging
import random
import select
import socket
import struct
import threading
import time

from ...dotdict import dotdict


log = logging.getLogger(__name__)
clock = getattr(time, 'monotonic', time.time)
IO_PORT = 2222
O_T_ADDRESS = 0x8000
T_O_ADDRESS = 0x8001
SOCKET_ITEMS = (O_T_ADDRESS, T_O_ADDRESS)
CYCLIC_CLASS1 = 0x01
MIN_RPI_US = 10000
MAX_RPI_US = 10000000
# A UDP datagram is already framed. The fixed CPF prefix contains the item count,
# Sequenced Address (ID and sequence), and Connected Data (CIP sequence).
_FRAME = struct.Struct('<HHHIIHHH')
_RANDOM = random.SystemRandom()


class ConnectionError(ValueError):
    """A Class 1 connection request the adapter cannot accept."""

    def __init__(self, message, *status):
        super(ConnectionError, self).__init__(message)
        self.status = status


def connection_id():
    return _RANDOM.randrange(1, 1 << 32)


def socket_item(kind, address):
    host, port = address
    # The IPv4 family is specified on the wire independently of the OS.
    return dotdict(type_id=kind, socket_address=dict(family=2, port=port, host=host))


def socket_endpoint(items, kind, host):
    """Read a unicast destination. A zero address or absent item uses the TCP peer."""
    for item in items:
        if item.type_id != kind:
            continue
        address = item.socket_address
        if address.family != 2 or not address.port:
            raise ValueError("Class 1 requires an IPv4 UDP destination")
        if address.host not in ('0.0.0.0', host):
            raise ValueError("Class 1 UDP destination must match the TCP peer")
        return host, address.port
    return host, IO_PORT


def encode_io(connection, sequence, data_sequence, payload):
    return _FRAME.pack(2, 0x8002, 8, connection, sequence, 0x00b1, len(payload) + 2,
                       data_sequence) + payload


def decode_io(datagram):
    """Decode an I/O datagram with the modeless Class 1 real-time format."""
    if len(datagram) < _FRAME.size:
        raise ValueError("Short Class 1 datagram")
    count, address, address_size, connection, sequence, data, size, data_sequence = _FRAME.unpack_from(datagram)
    if (count, address, address_size, data, size) != (2, 0x8002, 8, 0x00b1, len(datagram) - _FRAME.size + 2):
        raise ValueError("Invalid Class 1 datagram")
    return connection, sequence, data_sequence, datagram[_FRAME.size:]


class InputOnly(object):
    """Connection points and application data size for a fixed-size Input Only assembly."""

    def __init__(self, configuration, heartbeat, input_assembly, input_size):
        if not all(1 <= instance <= 65535 for instance in (configuration, heartbeat, input_assembly)):
            raise ValueError("Class 1 assembly instances must be in 1..65535")
        if not 1 <= input_size <= 509:
            raise ValueError("Small Forward Open supports 1..509 bytes of Class 1 input data")
        self.path = [
            {'class': 4}, {'instance': configuration},
            {'connection': heartbeat}, {'connection': input_assembly},
        ]
        self.input_size = input_size

    def parameters(self, rpi_us):
        if not MIN_RPI_US <= rpi_us <= MAX_RPI_US:
            raise ValueError("Class 1 RPI must be 10000..10000000 microseconds")
        return (
            dotdict(type=2, size=2, variable=0, RPI=rpi_us, connection_ID=0),
            dotdict(type=2, size=self.input_size + 2, variable=0, RPI=rpi_us,
                    connection_ID=connection_id()),
        )


class CyclicConnection(object):
    """State shared by the scanner and adapter sides of a modeless connection."""

    def __init__(self, peer, tx, rx, receive_size, produce, multiplier, owner=None):
        if not all(MIN_RPI_US <= params.API <= MAX_RPI_US and params.connection_ID for params in (tx, rx)):
            raise ValueError("Invalid negotiated Class 1 packet interval or connection ID")
        self.peer = peer
        self.owner = owner
        self.tx_id = tx.connection_ID
        self.rx_id = rx.connection_ID
        self.interval = tx.API / 1000000
        self.timeout = rx.API / 1000000 * (4 << multiplier)
        self.receive_size = receive_size
        self.produce = produce
        self.tx_sequence = self.data_sequence = 0
        self.rx_sequence = None
        self.latest = self.sent = None
        self.received_at = None
        self.next_send = clock()
        self.expires = self.next_send + max(10, self.timeout)

    def send(self, sock, now):
        payload = self.produce()
        self.tx_sequence = (self.tx_sequence + 1) & 0xffffffff
        if payload != self.sent:
            self.data_sequence = (self.data_sequence + 1) & 0xffff
        sock.sendto(encode_io(self.tx_id, self.tx_sequence, self.data_sequence, payload), self.peer)
        self.sent = payload
        # Skip missed intervals without accumulating drift or sending a burst.
        self.next_send += self.interval * (int((now - self.next_send) / self.interval) + 1)

    def receive(self, datagram, address, now):
        if address[0] != self.peer[0]:
            return False
        try:
            ident, sequence, _, payload = decode_io(datagram)
        except ValueError:
            return False
        if ident != self.rx_id or len(payload) != self.receive_size:
            return False
        if self.rx_sequence is not None and not 0 < ((sequence - self.rx_sequence) & 0xffffffff) < 0x80000000:
            return False
        self.rx_sequence = sequence
        self.latest = payload
        self.received_at = now
        self.expires = now + self.timeout
        return True


class Worker(object):
    """Own a UDP socket and service one cyclic connection until closed."""

    def __init__(self, sock, connection=None):
        self.socket = sock
        self.connection = connection
        self.condition = threading.Condition()
        self.closed = False
        self.thread = threading.Thread(target=self.run, name='enip-class1')
        self.thread.daemon = True
        self.thread.start()

    def run(self):
        try:
            while True:
                with self.condition:
                    if self.closed:
                        return
                    peer = self.connection
                    now = clock()
                    delay = .01
                    if peer and now >= peer.expires:
                        log.info("Class 1 connection to %r expired", peer.peer)
                        self.connection = peer = None
                        self.condition.notify_all()
                    if peer and now >= peer.next_send:
                        try:
                            peer.send(self.socket, now)
                        except socket.error as exc:
                            log.info("Class 1 send to %r failed: %s", peer.peer, exc)
                            self.connection = peer = None
                            self.condition.notify_all()
                    if peer:
                        delay = max(0, min(delay, min(peer.next_send, peer.expires) - clock()))
                if select.select([self.socket], [], [], delay)[0]:
                    datagram, address = self.socket.recvfrom(65535)
                    with self.condition:
                        # Forward Open can install the connection while select is waiting.
                        peer = self.connection
                        now = clock()
                        if peer and now < peer.expires and peer.receive(datagram, address, now):
                            self.condition.notify_all()
        except Exception:
            log.exception("Class 1 I/O worker failed")
        finally:
            with self.condition:
                self.closed = True
                self.connection = None
                self.condition.notify_all()
            self.socket.close()

    def receive(self, timeout):
        """Return the latest fresh assembly, or None if the wait or watchdog expires."""
        end = clock() + timeout
        with self.condition:
            while self.connection:
                now = clock()
                if self.connection.expires <= now:
                    return None
                if self.connection.latest is not None:
                    return self.connection.latest
                if now >= end:
                    return None
                self.condition.wait(min(end, self.connection.expires) - now)
            return None

    def close(self):
        with self.condition:
            self.closed = True
            self.condition.notify_all()
        self.thread.join()


def bound_socket(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(address)
    except BaseException:
        sock.close()
        raise
    return sock


class Adapter(object):
    """Accept a single cyclic, unicast Input Only connection for a status provider."""

    def __init__(self, profile, snapshot, address=('0.0.0.0', IO_PORT)):
        self.profile = profile
        self.snapshot = snapshot
        sock = bound_socket(address)
        self.address = sock.getsockname()
        try:
            self.worker = Worker(sock)
        except BaseException:
            sock.close()
            raise

    def close(self):
        self.worker.close()

    @staticmethod
    def identity(request):
        return request.connection_serial, request.O_vendor, request.O_serial

    def open_connection(self, request, address, items):
        if request.transport_class_triggers != CYCLIC_CLASS1:
            raise ConnectionError("Only cyclic Class 1 is supported", 0x0103)
        if request.connection_path.segment != self.profile.path:
            raise ConnectionError("Unknown Input Only assembly path", 0x012a)
        if request.O_T.redundant or request.T_O.redundant:
            raise ConnectionError("Class 1 redundant ownership is unsupported", 0x0125)
        for offset, params, size in (
            (0, request.O_T, 2),
            (1, request.T_O, self.profile.input_size + 2),
        ):
            if params.type != 2:
                raise ConnectionError("Class 1 requires unicast", 0x0123 + offset)
            if params.variable:
                raise ConnectionError("Class 1 requires a fixed size", 0x011f + offset)
            if params.size != size:
                raise ConnectionError("Invalid Class 1 connection size", 0x0127 + offset, size)
            if not MIN_RPI_US <= params.RPI <= MAX_RPI_US:
                raise ConnectionError("Unsupported Class 1 RPI", 0x0111)
        if request.connection_timeout_multiplier > 7 or not request.T_O.connection_ID:
            raise ConnectionError("Invalid Class 1 timeout or connection ID", 0x0108)
        try:
            destination = socket_endpoint(items, T_O_ADDRESS, address[0])
        except ValueError as exc:
            raise ConnectionError(str(exc), 0x0108)

        worker = self.worker
        with worker.condition:
            if worker.closed:
                raise ConnectionError("Class 1 adapter is stopped", 0x0110)
            if worker.connection and worker.connection.expires > clock():
                raise ConnectionError("Class 1 connection already in use", 0x0100)
            request.O_T.connection_ID = connection_id()
            request.O_T.API = request.O_T.RPI
            request.T_O.API = request.T_O.RPI
            worker.connection = CyclicConnection(
                destination, request.T_O, request.O_T, 0, self.payload,
                request.connection_timeout_multiplier,
                owner=(address[0], self.identity(request)),
            )
        return [socket_item(O_T_ADDRESS, self.address)]

    def close_connection(self, request, address):
        with self.worker.condition:
            peer = self.worker.connection
            if peer and peer.owner == (address[0], self.identity(request)):
                if request.connection_path.segment != self.profile.path:
                    raise ConnectionError("Incorrect Class 1 close path", 0x0117)
                self.worker.connection = None
                self.worker.condition.notify_all()
                return True
        return False

    def payload(self):
        payload = bytes(self.snapshot())
        if len(payload) != self.profile.input_size:
            raise ValueError("Class 1 snapshot size changed")
        return payload
