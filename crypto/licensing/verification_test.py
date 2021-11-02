# -*- coding: utf-8 -*-
import binascii
import codecs
import pytest
import json
import os

from dns.exception import DNSException
from .verification import (
    License, LicenseSigned, LicenseIncompatibility, Timespan,
    domainkey, domainkey_service, overlap_intersect,
    into_b64, into_hex, into_str, into_str_UTC, into_JSON, into_keys,
    author, issue, verify, load,
)
from .. import ed25519ll as ed25519

from ...history import parse_datetime, timestamp, parse_seconds, duration

dominion_sigkey = binascii.unhexlify( '431f3fb4339144cb5bdeb77db3148a5d340269fa3bc0bf2bf598ce0625750fdca991119e30d96539a70cd34983dd00714259f8b60a2163bdb748f3fc0cf036c9' )
awesome_sigkey = binascii.unhexlify(  '4e4d27b26b6f4db69871709d68da53854bd61aeee70e63e3b3ff124379c1c6147321ce7a2fb87395fe0ff9e2416bc31b9a25475aa2e2375d70f4c326ffd47eb4' )
enduser_seed = binascii.unhexlify( '00' * 32 )

machine_id_path=__file__.replace(".py", ".machine-id" )


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
    other = Timespan(
        timestamp( parse_datetime( '2021-01-01 00:00:00 Canada/Pacific' )),
        duration( parse_seconds( '1w' ))
    )
    start,length,begun,ended = overlap_intersect( None, None, other )
    assert into_str_UTC( start ) == "2021-01-01 08:00:00 UTC"
    assert into_str( length ) == "1w"
    assert into_str_UTC( begun ) == "2021-01-01 08:00:00 UTC"
    assert into_str_UTC( ended ) == "2021-01-08 08:00:00 UTC"

    start = timestamp( parse_datetime( '2021-01-01 00:00:00 Canada/Pacific' ))
    length = duration( parse_seconds( "1w" ))
    start,length,begun,ended = overlap_intersect( start, length, Timespan( None, None ))
    assert into_str_UTC( start ) == "2021-01-01 08:00:00 UTC"
    assert into_str( length ) == "1w"
    assert into_str_UTC( begun ) == "2021-01-01 08:00:00 UTC"
    assert into_str_UTC( ended ) == "2021-01-08 08:00:00 UTC"


    
def test_License_serialization():
    provenance = load( 'verification_test', extra=[os.path.dirname( __file__ )], confirm=False )
    with open( os.path.join( os.path.dirname( __file__ ), "verification_test.cpppo-licensing" )) as f:
        assert str( provenance ) == f.read()

    
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
    #print("ed25519 keypair: {sk}".format( sk=binascii.hexlify( keypair.sk )))
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
    _, awesome_pubkey = into_keys( awesome_keypair )
    
    print("Awesome, Inc. ed25519 keypair; Signing: {sk}".format( sk=binascii.hexlify( awesome_keypair.sk )))
    print("Awesome, Inc. ed25519 keypair; Public:  {pk_hex} == {pk}".format( pk_hex=into_hex( awesome_keypair.vk ), pk=into_b64( awesome_keypair.vk )))

    try:
        lic = License(
            author	= "Dominion Research & Development Corp.",
            product	= "Cpppo Test",
            author_domain = "dominionrnd.com",
            client	= "Awesome, Inc.",
            client_pubkey = awesome_pubkey,
            start	= "2021-09-30 11:22:33 Canada/Mountain",
            length	= "1y" )
    except DNSException:
        lic = License(
            author	= "Dominion Research & Development Corp.",
            product	= "Cpppo Test",
            author_domain = "dominionrnd.com",
            author_pubkey = dominion_sigkey[32:],
            client	= "Awesome, Inc.",
            client_pubkey = awesome_pubkey,
            start	= "2021-09-30 11:22:33 Canada/Mountain",
            length	= "1y" )
    # Obtain a signed Cpppo license for 2021-09-30 + 1y
    lic_prov = issue( lic, dominion_sigkey )

    # Create a signing key for Awesome, Inc.; securely hide it, and publish the base-64 encoded public key as a TXT RR at:
    # ethernet-ip-tool.cpppo-licensing._domainkey.awesome.com 300 IN TXT "v=DKIM1; k=ed25519; p=

    enduser_keypair = author( seed=enduser_seed )
    enduser_sigkey, enduser_pubkey = into_keys( enduser_keypair )
    print("End User, LLC ed25519 keypair; Signing: {sk}".format( sk=into_hex( enduser_keypair.sk )))
    print("End User, LLC ed25519 keypair; Public:  {pk_hex} == {pk}".format( pk_hex=into_hex( enduser_keypair.vk ), pk=into_b64( enduser_keypair.vk )))

    # Almost at the end of their Cpppo license, they issue a new License to End User, LLC
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
    # process for deploying an application to a new host:
    #
    # 1) Install software to target directory
    # 2) Obtain serialized LicenseSigned containing necessary License(s)
    # 3) Derive a new License, specialized for the host's machine-id UUID
    #    - This will not be a LicenseSigned
    # 4) Save to <application>.cpppo-licensing in application's config path

    # Lets specialize the license for a specific machine.  
    lic_host_dict = verify( drv_prov, confirm=False, machine=True, machine_id_path=machine_id_path )
    assert into_str( lic_host_dict['machine'] ) == "00010203-0405-4607-8809-0a0b0c0d0e0f"
    assert len( lic_host_dict['dependencies'] ) == 1

    lic_host = License( author="End User", product="application", author_pubkey=enduser_keypair,
                        confirm=False, machine_id_path=machine_id_path,
                        **lic_host_dict )
    lic_host_prov = issue( lic_host, enduser_keypair, confirm=False, machine_id_path=machine_id_path )
    lic_host_str = str( lic_host_prov )
    #print( lic_host_str )
    assert lic_host_str == """\
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
        "length":null,
        "machine":"00010203-0405-4607-8809-0a0b0c0d0e0f",
        "product":"application",
        "start":null
    },
    "signature":"f64wAgeIr1gPmRviu8lfDS1vP3L5/xG6Yf2HentNwQHR7tf4pgjY4Elx0uf9kmO0OtDlPWZP4gLPYiek1wQiAg=="
}"""
