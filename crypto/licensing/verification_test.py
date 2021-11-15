# -*- coding: utf-8 -*-
import binascii
import codecs
import copy
import json
import os
import pytest

from dns.exception import DNSException
from .verification import (
    License, LicenseSigned, LicenseIncompatibility, Timespan,
    KeypairPlaintext, KeypairEncrypted,
    domainkey, domainkey_service, overlap_intersect,
    into_b64, into_hex, into_str, into_str_UTC, into_JSON, into_keys,
    into_timestamp, into_duration,
    author, issue, verify, load, load_keys,
)
from .. import ed25519ll as ed25519

from ...history import parse_datetime, timestamp, parse_seconds, duration

dominion_sigkey			= binascii.unhexlify(
    '431f3fb4339144cb5bdeb77db3148a5d340269fa3bc0bf2bf598ce0625750fdca991119e30d96539a70cd34983dd00714259f8b60a2163bdb748f3fc0cf036c9' )
awesome_sigkey			= binascii.unhexlify(
    '4e4d27b26b6f4db69871709d68da53854bd61aeee70e63e3b3ff124379c1c6147321ce7a2fb87395fe0ff9e2416bc31b9a25475aa2e2375d70f4c326ffd47eb4' )
enduser_seed			= binascii.unhexlify( '00' * 32 )

username			= 'a@b.c'
password			= 'password'

machine_id_path			= __file__.replace( ".py", ".machine-id" )


def test_License_domainkey():
    """Ensure we can handle arbitrary UTF-8 domains, and compute the proper DKIM1 RR path"""
    assert domainkey_service( u"π" ) == 'xn--1xa'
    assert domainkey_service( u"π/1" ) ==  'xn---1-lbc'

    path, dkim_rr = domainkey( u"Some Product", "example.com" )
    assert path == 'some-product.cpppo-licensing._domainkey.example.com.'
    assert dkim_rr == None
    author_keypair = author( seed=b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' )
    path, dkim_rr = domainkey( u"ᛞᚩᛗᛖᛋ᛫ᚻᛚᛇᛏᚪᚾ᛬", "awesome-inc.com", author_pubkey=author_keypair )
    assert path == 'xn--dwec4cn7bwa4a4ci7a1b2lta.cpppo-licensing._domainkey.awesome-inc.com.'
    assert dkim_rr == 'v=DKIM1; k=ed25519; p=25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83/MH50='


def test_License_overlap():
    """A License can only issued while all the sub-Licenses are valid.  The start/length should "close"
    to encompass the start/length of any dependencies sub-Licenses, and any supplied constraints.

    """
    other = Timespan(
        timestamp( parse_datetime( '2021-01-01 00:00:00 Canada/Pacific' )),
        duration( parse_seconds( '1w' ))
    )
    start,length,begun,ended = overlap_intersect( None, None, other )
    assert into_str_UTC( start ) == "2021-01-01 08:00:00 UTC"
    assert into_str( length ) == "1w"
    assert into_str_UTC( begun ) == "2021-01-01 08:00:00 UTC"
    assert into_str_UTC( ended ) == "2021-01-08 08:00:00 UTC"

    start = into_timestamp( '2021-01-01 00:00:00 Canada/Pacific' )
    length = into_duration( "1w" )
    start,length,begun,ended = overlap_intersect( start, length, Timespan( None, None ))
    assert into_str_UTC( start ) == "2021-01-01 08:00:00 UTC"
    assert into_str( length ) == "1w"
    assert into_str_UTC( begun ) == "2021-01-01 08:00:00 UTC"
    assert into_str_UTC( ended ) == "2021-01-08 08:00:00 UTC"


def test_KeypairPlaintext_smoke():
    enduser_keypair		= author( seed=enduser_seed, why="from enduser seed" )
    kp_p			= KeypairPlaintext( sk=into_b64( enduser_seed ), vk=into_b64( enduser_keypair.vk ))
    kp_p_ser			= str( kp_p )
    assert kp_p_ser == """\
{
    "sk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ==",
    "vk":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
}"""
    kp_p_rec			= KeypairPlaintext( **json.loads( kp_p_ser ))
    assert str( kp_p_rec ) == kp_p_ser

    # We can also recover with various subsets of sk, vk
    kp_p2			= KeypairPlaintext( sk=kp_p.sk[:32] )
    kp_p3			= KeypairPlaintext( sk=kp_p.sk[:64] )
    kp_p4			= KeypairPlaintext( sk=kp_p.sk[:64], vk=kp_p.vk )

    assert str( kp_p2 ) == str( kp_p3 ) == str( kp_p4 )

    # And see if we can copy Serializable things properly
    kp_c1			= copy.copy( kp_p4 )
    assert str( kp_c1 ) == str( kp_p4 )

try:
    import chacha20poly1305
except:
    chacha20poly1305		= None

@pytest.mark.skipif( not chacha20poly1305, reason="Needs ChaCha20Poly1305" )
def test_KeypairEncrypted_smoke():
    enduser_keypair		= author( seed=enduser_seed, why="from enduser seed" )
    salt			= b'\x00' * 12
    kp_e			= KeypairEncrypted( salt=salt, sk=enduser_keypair.sk,
                                                    username=username, password=password )
    assert kp_e.into_keypair( username=username, password=password ) == enduser_keypair

    kp_e_ser			= str( kp_e )
    assert kp_e_ser == """\
{
    "salt":"000000000000000000000000",
    "seed":"d211f72ba97e9cdb68d864e362935a5170383e70ea10e2307118c6d955b814918ad7e28415e2bfe66a5b34dddf12d275"
}"""
    kp_r			= KeypairEncrypted( **json.loads( kp_e_ser ))
    assert str( kp_r ) == kp_e_ser

    # We can also reconstruct from just seed and salt
    kp_e2			= KeypairEncrypted( salt=salt, seed=kp_e.seed )
    assert str( kp_e2 ) == kp_e_ser
    assert kp_e.into_keypair( username=username, password=password ) \
        == kp_r.into_keypair( username=username, password=password ) \
        == kp_e2.into_keypair( username=username, password=password )

    awesome_keypair		= into_keys( awesome_sigkey )
    kp_a			= KeypairEncrypted( salt=b'\x01' * 12, sk=awesome_keypair[1],
                                                    username=username, password=password )
    assert kp_a.into_keypair( username=username, password=password )[1] == awesome_keypair[1]

    kp_a_ser			= str( kp_a )
    assert """\
{
    "salt":"010101010101010101010101",
    "seed":"aea5129b033c3072be503b91957dbac0e4c672ab49bb1cc981a8955ec01dc47280effc21092403509086caa8684003c7"
}""" == kp_a_ser

@pytest.mark.skipif( not chacha20poly1305, reason="Needs ChaCha20Poly1305" )
def test_KeypairEncrypted_load_keys():
    enduser_keypair		= author( seed=enduser_seed, why="from enduser seed" )
    (keyname,keypair,keycred),	= load_keys( username=username, password=password,
                                             extra=[os.path.dirname( __file__ )], filename=__file__ )
    assert keycred == dict( username=username, password=password )
    assert keypair.into_keypair( **keycred ) == enduser_keypair


def test_KeypairPlaintext_load_keys():
    enduser_keypair		= author( seed=enduser_seed, why="from enduser seed" )
    (keyname,keypair,keycred),	= load_keys( extension="cpppo-keypair-plaintext",
                                             extra=[os.path.dirname( __file__ )], filename=__file__ )
    assert keypair.into_keypair(**keycred) == enduser_keypair


def test_License_serialization():
    # Deduce the basename from our __file__ (note: this is destructuring a 1-element sequence from a
    # generator!)
    (provname,prov), = load( extra=[os.path.dirname( __file__ )], filename=__file__, confirm=False )
    with open( os.path.join( os.path.dirname( __file__ ), "verification_test.cpppo-licensing" )) as f:
        assert str( prov ) == f.read()


def test_License():
    try:
        lic = License(
            author	= "Dominion Research & Development Corp.",
            product	= "Cpppo Test",
            author_domain = "dominionrnd.com",
            start	= "2021-09-30 11:22:33 Canada/Mountain",
            length	= "1y" )
    except DNSException:
        lic = License(
            author	= "Dominion Research & Development Corp.",
            product	= "Cpppo Test",
            author_domain = "dominionrnd.com",
            author_pubkey = dominion_sigkey[32:],
            start	= "2021-09-30 11:22:33 Canada/Mountain",
            length	= "1y" )

    lic_str = str( lic )
    assert lic_str == """\
{
    "author":"Dominion Research & Development Corp.",
    "author_domain":"dominionrnd.com",
    "author_pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk=",
    "author_service":"cpppo-test",
    "client":null,
    "client_pubkey":null,
    "dependencies":null,
    "length":"1y",
    "machine":null,
    "product":"Cpppo Test",
    "start":"2021-09-30 17:22:33 UTC"
}"""
    assert lic.digest() == b'\xb9\x99\xe0{\n\x1f\x1f\xcd-R;~_\x1aX\xcb\xdb\xa9[4\x91\xc4\xd5v\xa5\xf4\x06z\xee\x9c\nE'
    assert lic.digest('hex', 'ASCII' ) == 'b999e07b0a1f1fcd2d523b7e5f1a58cbdba95b3491c4d576a5f4067aee9c0a45'
    assert lic.digest('base64', 'ASCII' ) == 'uZngewofH80tUjt+XxpYy9upWzSRxNV2pfQGeu6cCkU='
    keypair = ed25519.crypto_sign_keypair( dominion_sigkey[:32] )
    assert keypair.sk == dominion_sigkey
    assert lic.author_pubkey == b'\xa9\x91\x11\x9e0\xd9e9\xa7\x0c\xd3I\x83\xdd\x00qBY\xf8\xb6\n!c\xbd\xb7H\xf3\xfc\x0c\xf06\xc9'
    assert codecs.getencoder( 'base64' )( keypair.vk ) == (b'qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk=\n', 32)
    prov = LicenseSigned( lic, keypair.sk )

    machine_uuid = lic.machine_uuid( machine_id_path=machine_id_path )
    assert machine_uuid.hex == "000102030405460788090a0b0c0d0e0f"
    assert machine_uuid.version == 4
    
    prov_str = str( prov )
    assert prov_str == """\
{
    "license":{
        "author":"Dominion Research & Development Corp.",
        "author_domain":"dominionrnd.com",
        "author_pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk=",
        "author_service":"cpppo-test",
        "client":null,
        "client_pubkey":null,
        "dependencies":null,
        "length":"1y",
        "machine":null,
        "product":"Cpppo Test",
        "start":"2021-09-30 17:22:33 UTC"
    },
    "signature":"bw58LSvuadS76jFBCWxkK+KkmAqLrfuzEv7ly0Y3lCLSE2Y01EiPyZjxirwSjHoUf9kz9meeEEziwk358jthBw=="
}"""
    # Multiple licenses, some which truncate the duration of the initial License. Non-timezone
    # timestamps are assumed to be UTC.
    start, length = lic.overlap(
        License( author = "A", product = 'a', author_domain='a-inc.com', author_pubkey=keypair.vk, confirm=False,
                 start = "2021-09-29 00:00:00", length = "1w" ),
        License( author = "B", product = 'b', author_domain='b-inc.com', author_pubkey=keypair.vk, confirm=False,
                 start = "2021-09-30 00:00:00", length = "1w" ))
    # Default rendering of a timestamp is w/ milliseconds, and no tz info for UTC
    assert str( start ) == "2021-09-30 17:22:33.000"
    assert str( length ) == "5d6h37m27s"

    # Attempt to find overlap between non-overlapping Licenses.  Uses the local timezone for
    # rendering; force by setting environment variable TZ=Canada/Mountain for this test!
    with pytest.raises( LicenseIncompatibility ) as exc_info:
        start, length = lic.overlap(
            License( author = "A", product = 'a', author_domain='a-inc.com', author_pubkey=keypair.vk, confirm=False,
                     start = "2021-09-29 00:00:00", length = "1w" ),
            License( author = "B", product = 'b', author_domain='b-inc.com', author_pubkey=keypair.vk, confirm=False,
                     start = "2021-10-07 00:00:00", length = "1w" ))
    assert str( exc_info.value ).endswith(
        "License for B's 'b' from 2021-10-06 18:00:00 Canada/Mountain for 1w incompatible with others" )

def test_LicenseSigned():
    """Tests Licenses derived from other License dependencies."""
    awesome_keypair = author( seed=awesome_sigkey[:32] )
    awesome_pubkey, _ = into_keys( awesome_keypair )
    
    print("Awesome, Inc. ed25519 keypair; Signing: {sk}".format( sk=binascii.hexlify( awesome_keypair.sk )))
    print("Awesome, Inc. ed25519 keypair; Public:  {pk_hex} == {pk}".format( pk_hex=into_hex( awesome_keypair.vk ), pk=into_b64( awesome_keypair.vk )))

    try:
        # If we're connected to the Internet and can check DNS, lets try to confirm that DKIM public
        # key checking works properly.  First, lets try to create a License with the *wrong* public
        # key (doesn't match DKIM record in DNS).

        with pytest.raises( LicenseIncompatibility ) as exc_info:
            License(
                author	= "Dominion Research & Development Corp.",
                product	= "Cpppo Test",
                author_domain = "dominionrnd.com",
                author_pubkey = awesome_pubkey, # Purposely *wrong*; will not match cpppo-test.cpppo-licensing.. DKIM entry
                client	= "Awesome, Inc.",
                client_pubkey = awesome_pubkey,
                start	= "2021-09-30 11:22:33 Canada/Mountain",
                length	= "1y" )
        assert str( exc_info.value ).endswith(
            """License for Dominion Research & Development Corp.'s 'Cpppo Test': author key from DKIM qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk= != cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=""" )

        lic = License(
            author	= "Dominion Research & Development Corp.",
            product	= "Cpppo Test",
            author_domain = "dominionrnd.com",
            client	= "Awesome, Inc.",
            client_pubkey = awesome_pubkey,
            start	= "2021-09-30 11:22:33 Canada/Mountain",
            length	= "1y" )
    except DNSException:
        # No DNS; OK, let the test pass anyway.
        lic = License(
            author	= "Dominion Research & Development Corp.",
            product	= "Cpppo Test",
            author_domain = "dominionrnd.com",
            author_pubkey = dominion_sigkey[32:], # This is the correct key, which matches the DKIM entry
            client	= "Awesome, Inc.",
            client_pubkey = awesome_pubkey,
            start	= "2021-09-30 11:22:33 Canada/Mountain",
            length	= "1y" )
    # Obtain a signed Cpppo license for 2021-09-30 + 1y
    lic_prov = issue( lic, dominion_sigkey )

    # Create a signing key for Awesome, Inc.; securely hide it (or, print it for everyone to see,
    # just below! ;), and publish the base-64 encoded public key as a TXT RR at:
    # ethernet-ip-tool.cpppo-licensing._domainkey.awesome.com 300 IN TXT "v=DKIM1; k=ed25519; p=

    enduser_keypair		= author( seed=enduser_seed, why="from enduser seed" )
    enduser_pubkey, enduser_sigkey = into_keys( enduser_keypair )
    print("End User, LLC ed25519 keypair; Signing: {sk}".format( sk=into_hex( enduser_keypair.sk )))
    print("End User, LLC ed25519 keypair; Public:  {pk_hex} == {pk}".format( pk_hex=into_hex( enduser_keypair.vk ), pk=into_b64( enduser_keypair.vk )))

    # Almost at the end of their annual Cpppo license, they issue a new License to End User, LLC for
    # their Awesome EtherNet/IP Tool.
    drv = License(
        author	= "Awesome, Inc.",
        product	= "EtherNet/IP Tool",
        author_domain = "awesome-inc.com",
        author_pubkey = awesome_keypair.vk, # Avoid the dns.resolver.NXDOMAIN by providing the pubkey
        client = "End User, LLC",
        client_pubkey = enduser_pubkey,
        dependencies = [ lic_prov ],
        start	= "2022-09-29 11:22:33 Canada/Mountain",
        length	= "1y",
        confirm = False,
    )
    drv_prov = issue( drv, awesome_keypair.sk, confirm=False )
    assert "KZUN48PRuI55gCBkbjkiHPeatj+lmAnJPOS5cTa13Ik=" == drv_prov.b64digest()
    drv_prov_str = str( drv_prov )
    assert drv_prov_str == """\
{
    "license":{
        "author":"Awesome, Inc.",
        "author_domain":"awesome-inc.com",
        "author_pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
        "author_service":"ethernet-ip-tool",
        "client":"End User, LLC",
        "client_pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
        "dependencies":[
            {
                "license":{
                    "author":"Dominion Research & Development Corp.",
                    "author_domain":"dominionrnd.com",
                    "author_pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk=",
                    "author_service":"cpppo-test",
                    "client":"Awesome, Inc.",
                    "client_pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
                    "dependencies":null,
                    "length":"1y",
                    "machine":null,
                    "product":"Cpppo Test",
                    "start":"2021-09-30 17:22:33 UTC"
                },
                "signature":"TNVGYQjdGFFBJMIviAOLhPPuOefv+451OslLY4DJEK77LCS9LeJIaomv5sS8KHDkOE12eFOxi5aFXOw5O4jOCA=="
            }
        ],
        "length":"1y",
        "machine":null,
        "product":"EtherNet/IP Tool",
        "start":"2022-09-29 17:22:33 UTC"
    },
    "signature":"egUZM9vlF2y4DBCTtWNv3UC7nBRxSz4LZ12nOR+WSUktOrBbESsBuwQzjobNvPR2G+EZASRkY00bm/XqTzKsCg=="
}"""

    # Test the cpppo.crypto.licensing API, as used in applications.  A LicenseSigned is saved to an
    # <application>.cpppo-licensing file in the Application's configuration directory path.  The
    # process for deploying an application onto a new host:
    #
    # 1) Install software to target directory
    # 2) Obtain serialized LicenseSigned containing necessary License(s)
    #    - This is normally done in a company License Server, which holds the
    #      master license and issues specialized ones up to the purchased limits (eg. 10 machines)
    # 3) Derive a new License, specialized for the host's machine-id UUID
    #    - This will be a LicenseSigned by the company License server using the company's key,
    #    - It's client_pubkey will match this software installation's private key, and machine-id UUID
    # 4) Save to <application>.cpppo-licensing in application's config path

    # Lets specialize the license for a specific machine, and with a specific start time
    lic_host_dict = verify( drv_prov, confirm=False, machine=True, machine_id_path=machine_id_path,
                            start="2022-09-28 08:00:00 Canada/Mountain" )
    #print( into_JSON( lic_host_dict, indent=4, default=str ))
    assert """\
{
    "dependencies":[
        {
            "license":{
                "author":"Awesome, Inc.",
                "author_domain":"awesome-inc.com",
                "author_pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
                "author_service":"ethernet-ip-tool",
                "client":"End User, LLC",
                "client_pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
                "dependencies":[
                    {
                        "license":{
                            "author":"Dominion Research & Development Corp.",
                            "author_domain":"dominionrnd.com",
                            "author_pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk=",
                            "author_service":"cpppo-test",
                            "client":"Awesome, Inc.",
                            "client_pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
                            "dependencies":null,
                            "length":"1y",
                            "machine":null,
                            "product":"Cpppo Test",
                            "start":"2021-09-30 17:22:33 UTC"
                        },
                        "signature":"TNVGYQjdGFFBJMIviAOLhPPuOefv+451OslLY4DJEK77LCS9LeJIaomv5sS8KHDkOE12eFOxi5aFXOw5O4jOCA=="
                    }
                ],
                "length":"1y",
                "machine":null,
                "product":"EtherNet/IP Tool",
                "start":"2022-09-29 17:22:33 UTC"
            },
            "signature":"egUZM9vlF2y4DBCTtWNv3UC7nBRxSz4LZ12nOR+WSUktOrBbESsBuwQzjobNvPR2G+EZASRkY00bm/XqTzKsCg=="
        }
    ],
    "length":"1d6h",
    "machine":"00010203-0405-4607-8809-0a0b0c0d0e0f",
    "start":"2022-09-29 17:22:33 UTC"
}""" == into_JSON( lic_host_dict, indent=4, default=str )
    

    lic_host = License( author="End User", product="application", author_pubkey=enduser_keypair,
                        confirm=False, machine_id_path=machine_id_path,
                        **lic_host_dict )
    lic_host_prov = issue( lic_host, enduser_keypair, confirm=False, machine_id_path=machine_id_path )
    lic_host_str = str( lic_host_prov )
    assert """\
{
    "license":{
        "author":"End User",
        "author_domain":null,
        "author_pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
        "author_service":"application",
        "client":null,
        "client_pubkey":null,
        "dependencies":[
            {
                "license":{
                    "author":"Awesome, Inc.",
                    "author_domain":"awesome-inc.com",
                    "author_pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
                    "author_service":"ethernet-ip-tool",
                    "client":"End User, LLC",
                    "client_pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
                    "dependencies":[
                        {
                            "license":{
                                "author":"Dominion Research & Development Corp.",
                                "author_domain":"dominionrnd.com",
                                "author_pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk=",
                                "author_service":"cpppo-test",
                                "client":"Awesome, Inc.",
                                "client_pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
                                "dependencies":null,
                                "length":"1y",
                                "machine":null,
                                "product":"Cpppo Test",
                                "start":"2021-09-30 17:22:33 UTC"
                            },
                            "signature":"TNVGYQjdGFFBJMIviAOLhPPuOefv+451OslLY4DJEK77LCS9LeJIaomv5sS8KHDkOE12eFOxi5aFXOw5O4jOCA=="
                        }
                    ],
                    "length":"1y",
                    "machine":null,
                    "product":"EtherNet/IP Tool",
                    "start":"2022-09-29 17:22:33 UTC"
                },
                "signature":"egUZM9vlF2y4DBCTtWNv3UC7nBRxSz4LZ12nOR+WSUktOrBbESsBuwQzjobNvPR2G+EZASRkY00bm/XqTzKsCg=="
            }
        ],
        "length":"1d6h",
        "machine":"00010203-0405-4607-8809-0a0b0c0d0e0f",
        "product":"application",
        "start":"2022-09-29 17:22:33 UTC"
    },
    "signature":"Ltb81Zms8b8vFdWlx+0y8CBkJJeq626t64D4TQvuBXgkgZqgJPCnAWXp2bVZupLhpnEncyDoxLVcumYFWsaeDA=="
}""" == lic_host_str
