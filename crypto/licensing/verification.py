# -*- coding: utf-8 -*-
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

import ast
import base64
import codecs
import collections
import dns.resolver
import encodings.idna
import hashlib
import json
import logging
import uuid
import sys

from datetime import datetime

from ...misc		import timer
from ...automata	import type_str_base
from ...history.times	import parse_datetime, parse_seconds, timestamp, duration

log				= logging.getLogger( "licensing" )

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

try:
    str_maketrans		= str.maketrans
except: # Python2
    import string
    str_maketrans		= string.maketrans


def domainkey_service( product ):
    """Convert a UTF-8 product name into a ASCII DNS Domainkey service name, with 
    replacement for some symbols invalid in DNS names (TODO: incomplete).

        >>> domainkey_service( "Something Awesome v1.0" )
        'something-awesome-v1-0'

    """
    author_service		= product
    author_service		= domainkey_service.idna_encoder( author_service )[0]
    if sys.version_info[0] >= 3:
        author_service		= author_service.decode( 'ASCII' )
    author_service		= author_service.translate( domainkey_service.dns_trans )
    author_service		= author_service.lower()
    return author_service
domainkey_service.dns_trans	= str_maketrans( ' ._/', '----' )
domainkey_service.idna_encoder	= codecs.getencoder( 'idna' )
assert "a/b.c_d e".translate( domainkey_service.dns_trans ) == 'a-b-c-d-e'


def into_hex( binary, encoding='ASCII' ):
    return into_text( binary, 'hex', encoding )


def into_b64( binary, encoding='ASCII' ):
    return into_text( binary, 'base64', encoding )


def into_text( binary, decoding='hex', encoding='ASCII' ):
    """Convert binary bytes data to the specified decoding, (by default encoded to ASCII text), across
    most versions of Python 2/3.  If no encoding, resultant decoding symbols remains as un-encoded
    bytes.

    A supplied None remains None.

    """
    if binary is not None:
        assert isinstance( binary, bytes ), \
            "Cannot convert to {}: {!r}".format( decoding, binary )
        binary			= codecs.getencoder( decoding )( binary )[0]
        binary			= binary.replace( b'\n', b'' ) # some decodings contain line-breaks
        if encoding is not None:
            return binary.decode( encoding )
        return binary


def into_bytes( text, decodings=('hex', 'base64'), encoding='ASCII', ignore_invalid=True ):
    """Try to decode base-64 or hex bytes from the provided ASCII text.  Must work in Python 2, which
    is non-deterministic; a str may contain bytes or text.

    So, assume ASCII encoding, start with the most strict (least valid symbols) decoding codec
    first.  Then, try as simple bytes.

    """
    if not text:
        return None
    # First, see if the text looks like hex- or base64-encoded ASCII
    try:
        # Python3 'bytes' doesn't have .encode, Python2 binary data will raise UnicodeDecodeError
        text_enc		= text.encode( encoding )
        for c in decodings:
            try:
                binary		= codecs.getdecoder( c )( text_enc )[0]
                #log.debug( "Decoded {} {} bytes from: {!r}".format( len( binary ), c, text_enc ))
                return binary
            except Exception as exc:
                #log.debug( "Couldn't decode as {}: {!r}; {}".format( c, text_enc, exc ))
                pass
    except Exception as exc:
        #log.debug( "Couldn't encode as {}: {!r}; {!r}".format( encoding, text, exc ))
        pass
    # Finally, check if the text is already bytes (*possibly* bytes in Python2, as str ===
    # bytes; so this cannot be done before the decoding attempts, above)
    if isinstance( text, bytes ):
        return text
    if not ignore_invalid:
        raise RuntimeError( "Could not encode as {}, decode as {} or raw bytes: {!r}".format(
            encoding, ', '.join( decodings ), text ))


def into_keys( keypair ):
    """Return whatever Ed25519 (signing, public) keys are available in the provided Keypair or
     32/64-byte key material.

    Supports deserialization of keys from hex or base-64 encode public (32-byte) or secret/signing
    (64-byte) data.

    """
    try:
        # May be a Keypair namedtuple
        return keypair.sk, keypair.vk
    except AttributeError:
        pass
    # Not a Keypair.  First, see if it's a serialized public/private key.
    deserialized	= into_bytes( keypair )
    if deserialized:
        keypair		= deserialized
    # Finally, see if we've recovered a signing or public key
    if isinstance( keypair, bytes ):
        if len( keypair ) == 64:
            # Must be a 64-byte signing key, which also contains the public key
            return keypair[0:64], keypair[32:64]
        elif len( keypair ) == 32:
            # Can only contain a 32-byte public key
            return None, keypair[:32]
    # Unknown key material.
    return None, None


def into_str( maybe ):
    if maybe is not None:
        return str( maybe )


def into_str_UTC( ts, tzinfo=timestamp.UTC ):
    if ts is not None:
        return ts.render( tzinfo=tzinfo, ms=False, tzdetail=True )


def into_str_LOC( ts ):
    return into_str_UTC( ts, tzinfo=timestamp.LOC )


def into_JSON( thing, indent=None, encoding='UTF-8' ):
    def endict( x ):
        try:
            return dict( x )
        except Exception as exc:
            log.warning("Failed to JSON serialize {!r}".format( x ))
            raise
    # Unfortunately, Python2 json.dumps w/ indent emits trailing whitespace after "," making
    # tests fail.  Make the JSON separators whitespace-free, so the only difference between the
    # signed serialization and an pretty-printed indented serialization is the presence of
    # whitespace.
    separators			= (',', ':')
    text			= json.dumps(
        thing, sort_keys=True, indent=indent, separators=separators, default=endict )
    if encoding:
        return text.encode( encoding )
    return text


def domainkey( product, author_domain, author_service=None, author_pubkey=None ):
    """Compute and return the DNS path for the given product and domain.  Optionally, also returns the
    appropriate DKIM TXT RR record containing the author's public key (base-64 encoded), as per the
    RFC: https://www.rfc-editor.org/rfc/rfc6376.html

        >>> from .verification import author, domainkey
        >>> path, dkim_rr = domainkey( "Some Product", "example.com" )
        >>> path
        'some-product.cpppo-licensing._domainkey.example.com.'
        >>> dkim_rr

    
        # An Awesome, Inc. product
        >>> author_keypair = author( seed=b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' )
        >>> path, dkim_rr = domainkey( "Something Awesome v1.0", "awesome-inc.com", author_pubkey=author_keypair )
        >>> path
        'something-awesome-v1-0.cpppo-licensing._domainkey.awesome-inc.com.'
        >>> dkim_rr
        'v=DKIM1; k=ed25519; p=25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83/MH50='

    """
    if author_service is None:
        author_service		= domainkey_service( product )

    domain_name			= dns.name.from_text( author_domain )
    service_name		= dns.name.Name( [author_service, 'cpppo-licensing', '_domainkey'] )
    path_name			= service_name + domain_name
    path			= path_name.to_text()

    dkim			= None
    if author_pubkey:
        _, author_pubkey	= into_keys( author_pubkey )
        dkim			= '; '.join( "{k}={v}".format(k=k, v=v) for k,v in (
            ('v', 'DKIM1'),
            ('k', 'ed25519'),
            ('p', into_b64( author_pubkey )),
        ))

    return (path, dkim)


class Serializable( object ):
    """A base-class that provides a deterministic Unicode JSON serialization of every __slots__
    attribute, and a consistent dict representation of the same serialized data.  Access attributes
    directly to obtain underlying types.

    Uses __slots__ in derived classes to identify serialized attributes; traverses the class
    hierarchy's MRO to identify all attributes to serialize.  Output serialization is always in
    attribute-name sorted order.

    If an attribute requires special serialization handling (other than simple conversion to 'str'),
    then include it in the class' serializers dict, eg:

        serializers		= dict( special = into_hex )

    It is expected that derived class' constructors will deserialize when presented with keywords
    representing all __slots__.

    """

    __slots__			= ()
    serializers			= {}

    def keys( self ):
        for cls in type( self ).__mro__:
            for key in getattr( cls, '__slots__', []):
                yield key

    def serializer( self, key ):
        """Finds any custom serialization formatter specified for the given attribute, defaults to None.

        """
        for cls in type( self ).__mro__:
            try:
                return cls.serializers[key]
            except (AttributeError, KeyError):
                pass

    def __getitem__( self, key ):
        """Returns the serialization of the requested key, passing thru values without a serializer."""
        if key in self.keys():
            try:
                serialize	= self.serializer( key ) # (no Exceptions)
                value		= getattr( self, key ) # IndexError
                if serialize:
                    return serialize( value ) # conversion failure Exceptions
                return value
            except Exception as exc:
                log.info( "Failed to convert {class_name}.{key} with {serialize!r}".format(
                    class_name = self.__class__.__name__, key=key, serialize=serialize ))
                raise
        raise IndexError( key )

    def __str__( self ):
        return self.serialize( indent=4, encoding=None )

    def serialize( self, indent=None, encoding='UTF-8' ):
        """Return a binary 'bytes' serialization of the present object.  Serialize to JSON, assuming any
        complex sub-objects (eg. License, LicenseSigned) have a sensible dict representation.

        The default serialization (ie. with indent=None) will be the one used to create the digest
        """
        return into_JSON( self, indent=indent, encoding=encoding )

    def sign( self, author_sigkey, author_pubkey=None ):
        """Sign our default serialization, and (optionally) confirm that the supplied public key (which will
        be used to check the signature) is correct, by re-deriving the public key.

        """
        sigkey, pubkey	= into_keys( author_sigkey )
        assert sigkey, \
            "Invalid ed25519 signing key provided"
        if author_pubkey:
            # Re-derive and confirm supplied public key matches supplied signing key
            keypair		= ed25519.crypto_sign_keypair( sigkey[:32] )
            assert keypair.vk == author_pubkey, \
                "Mismatched ed25519 signing/public keys"
        signed			= ed25519.crypto_sign( self.serialize(), sigkey )
        signature		= signed[:64]
        return signature

    def digest( self, encoding=None, decoding=None ):
        """The SHA-256 hash of the serialization, as 32 bytes.  Optionally, encode w/ a named codec, eg
        "hex" or "base64".  Often, these will require a subsequent .decode( 'ASCII' ) to become a
        non-binary str.

        """
        binary			= hashlib.sha256( self.serialize() ).digest()
        if encoding is not None:
            binary		= codecs.getencoder( encoding )( binary )[0].replace(b'\n', b'')
            if decoding is not None:
                return binary.decode( decoding )
        return binary

    def hexdigest( self ):
        """The SHA-256 hash of the serialization, as a 256-bit (32 byte, 64 character) hex string."""
        return self.digest( 'hex', 'ASCII' )

    def b64digest( self ):
        return self.digest( 'base64', 'ASCII' )

    def __copy__( self ):
        """Create a new object by copying an existing object, taking __slots__ into account.

        """
        result			= self.__class__.__new__( self.__class__ )

        for cls in type( self ).__mro__:
            for key in getattr( cls, '__slots__', [] ):
                log.info( "copy .{key:-16s} from {src:16s} to {dst:16s}".format(
                    key=key, src=id(self), dst=id(result) ))
                setattr( result, copy.copy( getattri( self, var )))

        return result


class LicenseIncompatibility( Exception ):
    pass


Timespan = collections.namedtuple( 'Timespan', ('start', 'length') )

def overlap_intersect( start, length, other ):
    """Accepts a start/length, and either a License or a Timespan (something w/ start and length), and
    compute the intersecting start/length, and its begin and (if known) ended timestamps.
    
        start,length,begun,ended = overlap_intersect( start, length, other )

    """
    # Detect the situation where there is no computable overlap, and start, length is defined by one
    # pair or the other.
    if start is None:
        # This license has no defined start time (it is perpetual); other license determines
        assert length is None, "Cannot specify a length without a start timestamp"
        if other.start is None:
            # Neither specifies start at a defined time
            assert other.length is None, "Cannot specify a length without a start timestamp"
            return None,None,None,None
        if other.length is None:
            return other.start,other.length,other.start,None
        return other.start,other.length,other.start,other.start + other.length.seconds
    elif other.start is None:
        assert other.length is None, "Cannot specify a length without a start timestamp"
        if length is None:
            return start,length,start,None
        return start,length,start,start + length.seconds

    # Both have defined start times; begun defines beginning of potential overlap If the computed
    # ended time is <= begun, then there is no (zero) overlap!
    begun 		= max( start, other.start )
    ended		= None
    if length is None and other.length is None:
        # But neither have duration
        return start,length,begun,None

    # At least one length; ended is computable, as well as the overlap start/length
    if other.length is None:
        ended		= start + length.seconds
    elif length is None:
        ended		= other.start + other.length.seconds
    else:
        ended		= min( start + length.seconds, other.start + other.length.seconds )
    start		= begun
    length		= duration( 0 if ended <= begun else ended - begun )
    return start,length,begun,ended


class License( Serializable ):
    """Represents the details of a Licence from an author to a client (could be any client, if no
    client_pubkey provided).  Cannot be constructed unless the supplied License details are valid
    with respect to any supplied License dependencies.

    {
        "author": "Dominion Research & Development Corp.",
        "author_domain": "dominionrnd.com",
        "author_service": "cpppo",
        "client": "Awesome Inc.",
        "client_pubkey": "...",
        "dependencies": None,
        "product": "Cpppo",
        "length": "1y",
        "machine": None,
        "start": "2021-01-01 00:00:00+00:00")
    }

    Verifying a License
    -------------------

    A signed license is a claim by an Author that the License is valid; it is up to a recipient to
    check that the License also actually satisfies the constraints of any License dependencies.  A
    nefarious Author could create a License and properly sign it -- but not satisfy the License
    constraints.  License.verify(confirm=True) will do do this, as well as (optionally) retrieve and
    verify from DNS the public keys of the (claimed) signed License dependencies.

    Checking your License
    ---------------------

    Each module that uses cpppo.crypto.licensing checks that the final product's License or contains
    valid license(s) for itself, somewhere within the License dependencies tree.

    


    All start times are expressed in the UTC timezone; if we used the local timezone (as computed
    using get_localzone, wrapped to respect any TZ environment variable, and made available as
    timestamp.LOC), then serializations (and hence signatures and signature tests) would be
    inconsistent.

    Licenses are signed by the author using their signing key.  The corresponding public key is
    expected to be found in a DKIM entry, eg.:

        cpppo.licensing._domainkey.dominionrnd.com 300 IN TXT "v=DKIM1; k=ed25519; p=ICkF+6tTRKc8voK15Th4eTXMX3inp5jZwZSu4CH2FIc="

    """

    __slots__			= (
        'author', 'author_pubkey', 'author_domain', 'author_service', 'product',
        'client', 'client_pubkey',
        'dependencies',
        'start', 'length',
        'machine',
    )
    serializers			= dict(
        author_pubkey	= into_b64,
        client_pubkey	= into_b64,
        start		= into_str_UTC,
        length		= into_str,
        machine		= into_str,
    )

    def __init__( self, author, product,
                  author_domain=None,			# Needed for DKIM if no author_pubkey provided
                  author_pubkey=None,			# Normally, obtained from domain's DKIM1 TXT RR
                  author_service=None,			# Normally, derived from product name
                  client=None, client_pubkey=None,	# The client may be identified
                  dependencies=None,			# Any sub-Licenses
                  start=None, length=None,		# License may not be perpetual
                  machine=None,				# A specific host may be specified
                  machine_id_path=None,
                  confirm=None,				# Validate License dependencies' author_pubkey from DNS
                 ):
        self.author		= author
        self.author_domain	= author_domain
        self.author_service	= author_service or domainkey_service( product )
        self.product		= product

        self.client		= client
        _, self.client_pubkey	= into_keys( client_pubkey )

        # Reconstitute LicenseSigned provenance from any dicts provided
        self.dependencies	= None if dependencies is None else list(
            LicenseSigned( confirm=confirm, **prov ) if isinstance( prov, dict ) else prov
            for prov in dependencies
        )

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
            try:
                length		= parse_seconds( length )
                assert isinstance( length, (int, float) )
                length		= duration( length )
            except Exception as exc:
                raise LicenseIncompatibility(
                    "License length invalid: {length!r}".format( length=length ))


        self.start		= start
        self.length		= length

        if machine is not None:
            if not isinstance( machine, uuid.UUID ):
                machine		= uuid.UUID( machine )
            assert machine.version == 4
        self.machine		= machine

        # Obtain confirmation of the Author's public key; either given through the API, or obtained
        # from their domain's DKIM entry.
        assert author_pubkey or self.author_domain, \
            "Either an author_pubkey, or an author_domain/service must be provided"
        _, self.author_pubkey	= into_keys( author_pubkey )
        if self.author_pubkey is None:
            self.author_pubkey	= self.author_pubkey_query()

        # Only allow the construction of valid Licenses.
        self.verify( confirm=confirm, machine_id_path=machine_id_path )

    def author_pubkey_query( self ):
        """Obtain the author's public key.  This was either provided at License construction time, or can be
        obtained from a DNS TXT "DKIM" record.
        
        TODO: Cache

        Query the DKIM record for an author public key.  May be split into multiple strings:

            r = dns.resolver.query('default._domainkey.justicewall.com', 'TXT')
            for i in r:
            ...  i.to_text()
            ...
            '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9...Btx" "aPXTN/aI+cvS8...4KHoQqhS7IwIDAQAB;"'

        Fortunately, the Python AST for string literals handles this quite nicely:

            >>> ast.literal_eval('"abc" "123"')
            'abc123'
        """
        dkim_path, _dkim_rr	= domainkey( self.product, self.author_domain, author_service=self.author_service )
        log.info("Querying {domain} for DKIM service {service}: {dkim_path}".format(
            domain=self.author_domain, service=self.author_service, dkim_path=dkim_path ))
        # Python2/3 compatibility; use query vs. resolve
        records			= list( rr.to_text() for rr in dns.resolver.query( dkim_path, 'TXT' ))
        assert len( records ) == 1, \
            "Failed to obtain a single TXT record from {dkim_path}".format( dkim_path=dkim_path )
        # Parse the "..." "..." strings.  There should be no escaped quotes.
        dkim			= ast.literal_eval( records[0] )
        log.info("Parsing DKIM record: {dkim!r}".format( dkim=dkim ))
        p			= None
        for pair in dkim.split( ';' ):
            key,val 		= pair.strip().split( '=', 1 )
            if key.strip().lower() == "v":
                assert val.upper() == "DKIM1", \
                    "Failed to find DKIM record; instead found record of type/version {val}".format( val=val )
            if key.strip().lower() == "k":
                assert val.lower() == "ed25519", \
                    "Failed to find Ed25519 public key; instead was of type {val!r}".format( val=val )
            if key.strip().lower() == "p":
                p		= val.strip()
        assert p, \
            "Failed to locate public key in TXT DKIM record: {dkim}".format( dkim=dkim )
        p_binary		= into_bytes( p, ('base64',), 'ASCII' )
        return p_binary
        #return codecs.getdecoder( 'base64' )( codecs.getencoder( 'utf-8' )( p )[0] )[0]

    def overlap( self, *others ):
        """Compute the overlapping start/length that is within the bounds of this and other license(s).
        If they do not overlap, raises a LicenseIncompatibility Exception.

        """
        start, length		= self.start, self.length
        for other in others:
            # If we determine a 0-length overlap, we have failed.
            start,length,begun,ended \
                		= overlap_intersect( start, length, other )	
            '''
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
            '''
            if length is not None and length.seconds == 0:
                # Overlap was computable, and was zero
                raise LicenseIncompatibility(
                    "License for {author}'s {product!r} from {start} for {length} incompatible with others".format(
                        author	= other.author,
                        product	= other.product,
                        start	= into_str_LOC( other.start ),
                        length	= other.length,
                    ))
        return start, length

    def machine_uuid( self, machine_id_path=None):
        """Identify the machine-id as an RFC 4122 UUID v4. On Linux systems w/ systemd, get from
        /etc/machine-id, as a UUID v4: https://www.man7.org/linux/man-pages/man5/machine-id.5.html.
        On MacOS and Windows, use uuid.getnode(), which derives from host-specific data (eg. MAC
        addresses, serial number, ...).

        This UUID should be reasonably unique across hosts, but is not guaranteed to be.

        TODO: Include root disk UUID?
        """
        if machine_id_path is None:
            machine_id_path		= "/etc/machine-id" 
        try:
            with open( machine_id_path, 'r' ) as m_id:
                machine_id		= m_id.read().strip()
        except Exception as exc:
            # Node number is typically a much shorter integer; fill to required UUID length.
            machine_id			= "{:0>32}".format( hex( uuid.getnode())[2:] )
        try:
            machine_id			= into_bytes( machine_id, ('hex', ) )
            assert isinstance( machine_id, bytes ) and len( machine_id ) == 16
        except Exception as exc:
            raise RuntimeError( "Invalid Machine ID found: {!r}: {}".format( machine_id, exc ))
        machine_id			= bytearray( machine_id )
        machine_id[6]		       &= 0x0F
        machine_id[6]		       |= 0x40
        machine_id[8]		       &= 0x3F
        machine_id[8]		       |= 0x80
        machine_id			= bytes( machine_id )
        return uuid.UUID( into_hex( machine_id ))

    def verify( self, signature=None, confirm=None, author_pubkey=None, machine_id_path=None,
                **constraints ):
        """Verify that the License is valid:

            - Has properly signed License dependencies
              - Each public key can be confirmed, if desired
            - Complies with the bounds of any License dependencies
              - A sub-License must be issued while all License dependencies are active
            - Allows any constraints supplied.

        If it does, the constraints are returned, including this LicenseSigned added to the
        dependencies.  If no additional constraints are supplied, this will simply return the empty
        constraints dict on success.  The returned constraints would be usable in constructing a new
        License (assuming at least the necessary author, author_domain and product were defined).

        """
        success			= None

        if author_pubkey:
            _, author_pubkey	= into_keys( author_pubkey )
            assert author_pubkey, "Unrecognized author_pubkey provided"

        if author_pubkey and author_pubkey != self.author_pubkey:
            raise LicenseIncompatibility( 
                "License for {auth}'s {prod!r} public key mismatch".format(
                    auth	= self.author,
                    prod	= self.product,
                ))
        # Verify that the License's stated public key matches the one in the domain's DKIM.  Default
        # to True when confirm is None.
        if confirm or confirm is None:
            avkey	 	= self.author_pubkey_query()
            if avkey != self.author_pubkey:
                raise LicenseIncompatibilty(
                    "License for {auth}'s {prod!r}: author key from DKIM {found} != {claim}".format(
                        auth	= self.author,
                        prod	= self.product,
                        found	= akey,
                        claim	= self.author_pubkey,
                    ))
        # Verify that the License signature was indeed produced by the signing key corresponding to the
        # provided public key
        if signature:
            try:
                ed25519.crypto_sign_open( signature + self.serialize(), self.author_pubkey )
            except Exception as exc:
                raise LicenseIncompatibility( 
                    "License for {auth}'s {prod!r}: signature mismatch: {sig!r}; {exc}".format(
                        auth	= self.author,
                        prod	= self.product,
                        sig	= signature,
                        exc	= exc,
                    ))

        # Verify any License dependencies are valid; signed w/ DKIM specified key, License OK.
        # When verifying License dependencies, we don't supply the constraints, because we're not
        # interested in sub-Licensing these Licenses, only verifying them.
        for prov in ( LicenseSigned( confirm=confirm, **d ) for d in self.dependencies or [] ):
            try:
                prov.verify( confirm=confirm )
                assert prov.license.client_pubkey is None or prov.license.client_pubkey == self.author_pubkey, \
                    "sub-License public key {client_pubkey} doesn't match Licence's public key {author_pubkey}".format(
                        client_pubkey	= to_b64( prov.license.client_pubkey ),
                        author_pubkey	= to_b64( self.author_pubkey ),
                    )
            except Exception as exc:
                raise LicenseIncompatibility(
                    "License for {auth}'s {prod!r}; sub-License for {dep_auth}'s {dep_prod!r} invalid: {exc}".format(
                        auth		= self.author,
                        prod		= self.product,
                        dep_auth	= prov.license.author,
                        dep_prod	= prov.license.product,
                        exc		= exc,
                    ))

        # Enforce all constraints, returning a dict suitable for creating a specialized License, if
        # a signature was provided; if not, we cannot produce a specialized sub-License, and must
        # fail.  

        # Verify all sub-license start/length durations comply with this License' duration.
        # Remember, these start/length specify the validity period of the License to be
        # sub-licensed, not the execution time of the installation!

        # TODO: Implement License expiration date, to allow a software deployment to time out and
        # refuse to run after a License as expired, forcing the software owner to obtain a new
        # License with a future expiration.  Typically, Cpppo installations are perpetual; if
        # installed with a valid License, they will continue to work without expiration.  However,
        # other software authors may want to sell software that requires issuance of new Licenses.
        try:
            start, length	= self.overlap( *( ls.license for ls in self.dependencies or [] ))
        except LicenseIncompatibility as exc:
            raise LicenseIncompatibility(
                "License for {auth}'s {prod!r}; sub-{exc}".format(
                    auth	= self.author,
                    prod	= self.product,
                    exc		= exc,
                ))

        # Apply any supplied start/length constraints to the computed License start/length in order
        # to validate their consistency with the sub-License start/lengths.
        if constraints.get('start') is not None or constraints.get('length') is not None:
            start, length, _, _	= overlap_intersect( start, length, Timespan(
                contraints.get( 'start' ), contraints.get( 'length' )))

        # Default 'machine' constraints to the local machine UUID.  If no constraints and
        # self.machine is None, we don't need to do anything, because the License is good for any
        # machine.  Use machine=True to force constraints to include the current machine UUID.
        machine			= None
        if self.machine or constraints.get( 'machine' ):
            # Either License or constraints specify a machine (so we have to verify).
            machine_uuid	= self.machine_uuid( machine_id_path=machine_id_path )
            if self.machine not in (None, True) and self.machine != machine_uuid:
                raise LicenseIncompatibility(
                    "License for {auth}'s {prod!r} specifies Machine ID {required}; found {detected}".format(
                        auth	= self.author,
                        prod	= self.product,
                        required= self.machine,
                        detected= machine_uuid,
                    ))
            machine_const	= constraints.get( 'machine' )
            if machine_const not in (None, True) and machine_const != machine_uuid:
                raise LicenseIncompatibility(
                    "Constraints on {auth}'s {prod!r} specifies Machine ID {required}; found {detected}".format(
                        auth	= self.author,
                        prod	= self.product,
                        required= machine_const,
                        detected= machine_uuid,
                    ))
            # Finally, unless the supplied 'machine' constraint was explicitly None (indicating that
            # the caller desires a machine-agnostic sub-License), default to constrain the License to
            # this machine.
            if machine_const is not None:
                constraints['machine'] = machine_uuid

        log.normal( "License for {auth}'s {prod!r} is valid from {start} for {length} on machine {machine}".format(
            auth	= self.author,
            prod	= self.product,
            start	= into_str_LOC( start ),
            length	= length,
            machine	= into_str( machine ) or into_str( constraints.get( 'machine' )) or '(any)',
        ))

        # Finally, now that the License, all License dependencies and any supplied constraints have
        # been verified, augment the constraints with this LicenseSigned as one of the dependencies.
        if constraints:
            assert signature is not None, \
                "Attempt to issue a sub-License of an un-signed License"
            constraints.setdefault( 'dependencies', [] )
            constraints['dependencies'].append( dict(
                LicenseSigned( license=self, signature=signature, confirm=confirm )
            ))

        return constraints


class LicenseSigned( Serializable ):
    """A License and its Ed25519 Signature provenance.  Only a LicenseSigned (and confirmation of the
    author's public key) proves that a License was actually issued by the purported author.  It is
    expected that authors will only sign a valid License.

    The public key of the author must be confirmed through independent means.  One typical means is by
    checking publication on the author's domain (the default behaviour w/ confirm=None), eg.:

        awesome-tool.cpppo-licensing._domainkey.awesome-inc.com 86400 IN TXT "v=DKIM1; k=ed25519; p=PW847sz.../M+/GZc="


    Authoring a License
    -------------------
    
    A software issuer (or end-user, in the case of machine-specific or numerically limited Licenses)
    must create new Licenses.
    
        >>> from cpppo.crypto.licensing import author, issue, verify
    
    First, create a Keypair, including both signing (private, .sk) and verifying (public, .vk) keys:

        >>> signing_keypair = author( seed=b'our secret 32-byte seed material' )

    Then, create a License, identifying the author by their public key, and the product.  This
    example is a perpetual license (no start/length), for any machine.

        >>> license = License( author = "Awesome, Inc.", product = "Awesome Tool", \
                author_domain = "awesome-inc.com", author_pubkey = signing_keypair.vk, \
                confirm=False ) # since awesome-inc.com doesn't actually exist...

    Finally, issue the LicenseSigned containing the License and its Ed25519 Signature provenance:

        >>> provenance = issue( license, signing_keypair, confirm=False )
        >>> provenance_ser = provenance.serialize( indent=4 )
        >>> print( provenance_ser.decode( 'utf-8' ) )
        {
            "license":{
                "author":"Awesome, Inc.",
                "author_domain":"awesome-inc.com",
                "author_pubkey":"PW847szICqnQBzbdr5TAoGO26RwGxG95e3Vd/M+/GZc=",
                "author_service":"awesome-tool",
                "client":null,
                "client_pubkey":null,
                "dependencies":null,
                "length":null,
                "machine":null,
                "product":"Awesome Tool",
                "start":null
            },
            "signature":"MiOGUpkv6/RWzI/C/VP1Ncn7N4WZa0lpiVzETZ4CJsLSo7qGLxIx+X+4tal16CcT+BUW1cDwJtcTftI5z+RHAQ=="
        }


    De/Serializing Licenses
    -----------------------
    
    Licenses are typically stored in files, in the configuration directory path of the application.


    Validating Licenses
    -------------------

    Somewhere in the product's code, the License is loaded and validated.

        import json
        >>> provenance_dict = json.loads( provenance_ser )
        >>> provenance_load = LicenseSigned( confirm=False, **provenance_dict )
        >>> print( provenance_load )
        {
            "license":{
                "author":"Awesome, Inc.",
                "author_domain":"awesome-inc.com",
                "author_pubkey":"PW847szICqnQBzbdr5TAoGO26RwGxG95e3Vd/M+/GZc=",
                "author_service":"awesome-tool",
                "client":null,
                "client_pubkey":null,
                "dependencies":null,
                "length":null,
                "machine":null,
                "product":"Awesome Tool",
                "start":null
            },
            "signature":"MiOGUpkv6/RWzI/C/VP1Ncn7N4WZa0lpiVzETZ4CJsLSo7qGLxIx+X+4tal16CcT+BUW1cDwJtcTftI5z+RHAQ=="
        }
        >>> verify( provenance_load, confirm=False )
        {}

    """

    __slots__			= ('license', 'signature')
    serializers			= dict(
        signature	= into_b64,
    )

    def __init__( self, license, author_sigkey=None, signature=None, confirm=None, machine_id_path=None ):
        """Given an ed25519 signing key (32-byte private + 32-byte public), produce the provenance
        for the supplied License. 

        Normal constructor calling convention to take a License and a signing key and create
        a signed provenance:

            LicenseSigned( <License>, <Keypair> )

        To reconstruct from a dict (eg. recovered from a .cpppo-license file):

            LicenseSigned( **provenance_dict )

        """
        assert isinstance( license, (License, dict) ), \
            "Require a License or its serialization dict, not a {!r}".format( license )
        self.license		= License( confirm=confirm, **license ) if isinstance( license, dict ) else license

        assert signature or author_sigkey, \
            "Require either signature, or the means to produce one via the author's signing key"
        if author_sigkey and not signature:
            # Sign our default serialization, also confirming that the public key matches
            self.signature	= self.license.sign( author_sigkey, self.license.author_pubkey )
        elif signature:
            # Could be a hex-encoded signature on deserialization, or a 64-byte signature.  If both
            # signature and author_sigkey, we'll just be confirming the supplied signature, below.
            self.signature	= into_bytes( signature, ignore_invalid=False )

        self.verify(
            author_pubkey	= author_sigkey,
            confirm		= confirm,
            machine_id_path	= machine_id_path )

    def verify( self, author_pubkey=None, signature=None, confirm=None, machine_id_path=None,
                **constraints ):
        return self.license.verify(
            author_pubkey	= author_pubkey or self.license.author_pubkey,
            signature		= signature or self.signature,
            confirm		= confirm,
            machine_id_path	= machine_id_path,
            **constraints )


def author( seed=None ):
    """Prepare to author Licenses, by creating an Ed25519 keypair."""
    keypair			= ed25519.crypto_sign_keypair( seed )
    log.warning("Created Ed25519 signing keypair w/ Public key: {vk_b64}".format(
        vk_b64=into_b64( keypair.vk )))
    return keypair


def issue( license, author_sigkey, signature=None, confirm=None, machine_id_path=None ):
    """If possible, issue the license signed with the supplied signing key.  Ensures that the license
    is allowed to be issued, by verifying the signatures of the tree of dependent license(s) if any.

    The holder of an author secret key can issue any license they wish (so long as it is compatible
    with any License dependencies).

    Generally, a license may be issued if it is more "specific" (less general) than any License
    dependencies.  For example, a License could specify that it can be used on *any* 1 installation.
    The holder of the license may then issue a License specifying a certain computer and
    installation path.  The software then confirms successfully that the License is allocated to
    *this* computer, and that the software is installed at the specified location.

    Of course, this is all administrative; any sufficiently dedicated programmer can simply remove
    the License checks from the software.  However, such people are *not* Clients: they are simply
    thieves.  The issuance and checking of Licenses is to help support ethical Clients in confirming
    that they are following the rules of the software author.

    """
    return LicenseSigned(
        license,
        author_sigkey,
        signature	= signature,
        confirm		= confirm,
        machine_id_path	= machine_id_path )


def verify( provenance, author_pubkey=None, signature=None, confirm=None, machine_id_path=None,
            **constraints ):
    """Verify that the supplied License or LicenseSigned contains a valid signature, and that the
    License follows the rules in all of its License dependencies.  Optionally, confirm the validity
    of any public keys.

    Apply any additional constraints, returning a License serialization dict satisfying them.  If
    you plan to issue a new LicenseSigned, it is recommended to include your author, author_domain
    and product names, and perhaps also the client and client_pubkey of the intended License
    recipient.

    Works with either a License and signature= keyword parameter, or a LicenseSigned provenance.

    """
    return provenance.verify(
        author_pubkey	= author_pubkey,
        signature	= signature or provenance.signature,
        confirm		= confirm,
        machine_id_path	= machine_id_path,
        **constraints )
    
