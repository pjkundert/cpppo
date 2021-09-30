
#
# Cpppo -- Communication Protocol Python Parser and Originator
#
# Copyright (c) 2021, Hard Consulting Corporation.
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

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2021 Dominion Research & Development Corp."
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

import collections
import hashlib
import json

from datetime import datetime

from ...misc		import timer
from ...automata	import type_str_base
from ...history.times	import parse_datetime, parse_seconds, timestamp, duration

# Try a globally installed ed25519ll possibly with a CTypes binding
try:
    import ed25519ll as ed25519
except ImportError:
    # Otherwise, try our local Python-only ed25519ll derivation
    try:
        from .. import ed25519ll as ed25519
    except ImportError:
        # Fall back to the very slow D.J.Bernstein Python reference implementation
        from .. import ed25519

from collections import namedtuple

Timespan			= namedtuple("Timespan", ('start', 'length'))

class License( object ):
    """Represents the details of a Licence.  If a header is supplied, it's signature is validated, or if
    a signer (private key) is supplied, a header with signature is produced.  Cannot be constructed
    unless the supplied License details are valid with respect to any supplied License dependencies.

    {
        "author": "Dominion Research & Development Corp.",
        "client": "Awesome Inc.",
        "dependencies": None,
        "product": "Cpppo",
        "timespan": ("2021-01-01 00:00:00+00:00", "1y")
    }

    """
    def __init__( self, author, product,  signer=None, dependencies=None, start=None, length=None ):
        self.author		= author
        self.product		= product
        self.dependencies	= dependencies

        # A License usually has a timespan of start timestamp and duration length.  These cannot
        # exceed the timespan of any License dependencies.  First, get any supplied start time as a
        # cpppo.history.timestamp, and any duration length as a number of seconds.  We don't
        # need/want to support ambiguous local timezone abbreviations, here, so use the simpler
        # parse_datetime interface, instead of letting timestamp parse it.
        if start is not None:
            if isinstance( start, type_str_base ):
                start		= parse_datetime( start )
            if isinstance( start, datetime ):
                start		= timestamp( start )
            assert isinstance( start, timestamp )
        if length is not None:
            length		= parse_seconds( length )
            assert isinstance( length, (int, float) )
            length		= duration( length )

        self.start		= start
        self.length		= length

    def __hash__( self ):
        """The SHA-256 hash of the License serialization, as a 256-bit (32-byte) bytes string."""
        return hashlib.sha256( str( self )).digest()

    __keys			= ['author', 'product', 'dependencies', 'start', 'length']
    def keys( self ):
        return self.__keys

    def __getitem__( self, key ):
        """When accessing as a dict entry, return values as a str.  Access the attributes directly to
        get their raw data types

        """
        if key in self.__keys:
            return str( getattr( self, key ))
        return IndexError( key )

    def __str__( self ):
        """A deterministic serialization of a License."""
        return json.dumps( dict( self ), sort_keys=True )


class LicenseProvenance( object ):
    """The hash and ed25519 signature for a License. """
    pass


def issue( lic, author ):
    """If possible, issue the license signed with the supplied signing key.  Ensures that the license
    is allowed to be issued, by verifying the signatures of the tree of dependent license(s) if any.

    The holder of an author secret key can issue any license they wish (so long as it is compatible
    with any License dependencies).

    """
    prov			= None
    return prov


def check( lic, prov ):
    pass
