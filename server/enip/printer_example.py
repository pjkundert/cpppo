"""Printer simulator with a cyclic status assembly and explicit job tags."""

from __future__ import absolute_import, print_function

import argparse
import struct
import sys

from . import class1, device
from .main import main as enip_main


PROFILE = class1.InputOnly(configuration=151, heartbeat=152, input_assembly=100, input_size=8)
TAGS = ['PrinterFlags=USINT', 'PaperLevel=USINT', 'PrintData=USINT[64]', 'SubmitJob=UDINT']


def main(argv=None, **kwds):
    """Start EtherNet/IP with an eight-byte Class 1 input assembly."""
    args = argparse.ArgumentParser(add_help=False)
    args.add_argument('--io-address', default='0.0.0.0:2222', metavar='IP:PORT')
    options, remaining = args.parse_known_args(argv)
    if '-h' in remaining or '--help' in remaining:
        args.print_help()
        return enip_main(argv=remaining, **kwds)
    host, separator, port = options.io_address.rpartition(':')
    if not separator or not port.isdigit() or int(port) > 65535:
        args.error('--io-address requires an IPv4 address and port')

    def status():
        # The job number acknowledges a submission to the simulated printer.
        values = [device.lookup(*device.resolve_tag(tag)) for tag in
                  ('PrinterFlags', 'PaperLevel', 'SubmitJob')]
        return struct.pack('<BBHI', values[0][0], values[1][0], 0, values[2][0])

    adapter = class1.Adapter(PROFILE, status, (host, int(port)))
    try:
        return enip_main(argv=remaining + TAGS, class1_adapter=adapter, **kwds)
    finally:
        adapter.close()


if __name__ == '__main__':
    sys.exit(main())
