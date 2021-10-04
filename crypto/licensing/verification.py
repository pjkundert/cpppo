
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

import codecs
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


def to_hex( binary ):
    """Convert binary bytes data to UTF-8 hexadecimal, across most versions of Python 2/3.

    """
    assert isinstance( binary, bytes )
    return codecs.getencoder( 'hex' )( binary )[0].decode( 'utf-8' )


class Serializable( object ):
    """A base-class that provides a deterministic Unicode JSON serialization of every __slots__
    attribute, and a consistent dict representation of the same serialized data.  Access attributes
    directly to obtain underlying types.

    Uses __slots__ in derived classes to identify serialized attributes; traverses the class
    hierarchy's MRO to identify all attributes to serialize.  Output serialization is always in
    attribute-name sorted order.

    If an attribute requires special serialization handling (other than simple conversion to 'str'),
    then include it in the class' serializers dict, eg:

        serializers		= dict( special = to_hex )

    """

    __slots__			= ()
    serializers			= {}

    def keys( self ):
        for cls in type( self ).__mro__:
            for key in getattr( cls, '__slots__', []):
                yield key

    def serializer( self, key ):
        """Finds any custom serialization formatter specified for the given attribute."""
        for cls in type( self ).__mro__:
            try:
                return cls.serializers[key]
            except (AttributeError, KeyError):
                pass
        return str

    def __getitem__( self, key ):
        if key in self.keys():
            value		= getattr( self, key )
            return self.serializer( key )( value )
        raise IndexError( key )

    def __str__( self ):
        return json.dumps( dict( self ), sort_keys=True )

    def serialize( self ):
        return str( self ).encode( 'utf-8' )
    
    def digest( self ):
        """The SHA-256 hash of the serialization, as 32 bytes."""
        return hashlib.sha256( self.serialize() ).digest()

    def hexdigest( self ):
        """The SHA-256 hash of the serialization, as a 256-bit (32 byte, 64 character) hex string."""
        return to_hex( self.digest() )



class LicenseIncompatibility( Exception ):
    pass


class License( Serializable ):
    """Represents the details of a Licence.  If a header is supplied, it's signature is validated, or if
    a signer (private key) is supplied, a header with signature is produced.  Cannot be constructed
    unless the supplied License details are valid with respect to any supplied License dependencies.

    {
        "author": "Dominion Research & Development Corp.",
        "client": "Awesome Inc.",
        "dependencies": None,
        "product": "Cpppo",
        "start": "2021-01-01 00:00:00+00:00"
        "length": "1y")
    }

    All times are expressed in the UTC timezone; if we used the local timezone (as computed using
    get_localzone, wrapped to respect any TZ environment variable, and made available as
    timestamp.LOC), then serializations (and hence signatures and signature tests) would be
    inconsistent.

    """

    __slots__			= ('author', 'product', 'dependencies', 'start', 'length')
    serializers			= {'start': lambda t: t.render( tzinfo=timestamp.UTC, ms=False, tzdetail=True )}

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

    def overlap( self, *others ):
        """Compute the overlapping start/length that is within the bounds of this and other license(s).
        If they do not overlap, raises a LicenseIncompatibility Exception.

        """
        start, length		= self.start, self.length
        for other in others:
            if start is None:
                # This license has no defined start time (it is perpetual); other license determines
                start, length	= other.start, other.length
                continue
            if other.start is None:
                # This license starts at a defined time, while the other doesn't
                continue
            # Both licenses have defined start times; latest defines beginning of overlap
            latest		= max( start, other.start )
            ending		= None
            if length is None and other.length is None:
                # But neither have duration
                start		= latest
                continue
            elif other.length is None:
                ending		= start + length.seconds
            elif length is None:
                ending		= other.start + other.length.seconds
            else:
                ending		= min( start + length.seconds, other.start + other.length.seconds )
            if ending <= latest:
                raise LicenseIncompatibility(
                    "License for {author}'s {product!r} ({o_s} for {o_l}) incompatible with others ({s} for {l})".format(
                        author	= other.author,
                        product	= other.product,
                        o_s	= other.start.render(tzinfo=timestamp.LOC, ms=False, tzdetail=True),
                        o_l	= other.length,
                        s	= start.render(tzinfo=timestamp.LOC, ms=False, tzdetail=True),
                        l	= length ))
            start, length	= latest, duration( ending - latest )
        return start, length
        

class LicenseProvenance( Serializable ):
    """The hash and ed25519 signature for a License. """

    __slots__			= ('license', 'license_digest', 'signature')
    serializers			= {'license_digest': to_hex, 'signature': to_hex }

    def __init__( self, lic, signer ):
        """Given an ed25519 signing key (32-byte private + 32-byte public), produce the provenance
        for the supplied License"""
        self.license		= lic
        self.license_digest	= lic.digest()

        # Confirm the signing key.  1st 32 bytes are private key, then (derived) public key.
        keypair			= ed25519.crypto_sign_keypair( signer[:32] )
        if len( signer ) > 32:
            assert signer == keypair.sk, \
                "Invalid ed25519 signing key provided"
        lic_signed		= ed25519.crypto_sign( lic.serialize(), signer )
        self.signature		= lic_signed[:64]


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
