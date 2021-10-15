# -*- coding: utf-8 -*-
import binascii
import codecs
import pytest
import json

from dns.exception import DNSException
from .verification import (
    License, LicenseSigned, LicenseIncompatibility,
    domainkey, author, issue, verify, into_b64,
)
from .. import ed25519ll as ed25519


dominion_sigkey = binascii.unhexlify( '431f3fb4339144cb5bdeb77db3148a5d340269fa3bc0bf2bf598ce0625750fdca991119e30d96539a70cd34983dd00714259f8b60a2163bdb748f3fc0cf036c9' )
awesome_sigkey = binascii.unhexlify(  '4e4d27b26b6f4db69871709d68da53854bd61aeee70e63e3b3ff124379c1c6147321ce7a2fb87395fe0ff9e2416bc31b9a25475aa2e2375d70f4c326ffd47eb4' )


def test_License_domainkey():
    """Ensure we can handle arbitrary UTF-8 domains, and compute the proper DKIM1 RR path"""
    path, dkim_rr = domainkey( "Some Product", "example.com" )
    assert path == 'some-product.cpppo-licensing._domainkey.example.com.'
    assert dkim_rr == None
    author_keypair = author( seed=b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' )
    path, dkim_rr = domainkey( u"ᛞᚩᛗᛖᛋ᛫ᚻᛚᛇᛏᚪᚾ᛬", "awesome-inc.com", author_pubkey=author_keypair )
    assert path == 'xn--dwec4cn7bwa4a4ci7a1b2lta.cpppo-licensing._domainkey.awesome-inc.com.'
    assert dkim_rr == 'v=DKIM1; k=ed25519; p=25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83/MH50='


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
    "product":"Cpppo Test",
    "start":"2021-09-30 17:22:33 UTC"
}"""
    assert lic.digest() == b'\xa1\x0ek\xcbDa\xde\xd4\xa0;\xb0\xa5\xa8\xab0c\xc9\xbc\xafo\x12\xa9%\xf2w\xbc\xec^m\rfi'
    assert lic.digest('hex', 'ASCII' ) == 'a10e6bcb4461ded4a03bb0a5a8ab3063c9bcaf6f12a925f277bcec5e6d0d6669'
    assert lic.digest('base64', 'ASCII' ) == 'oQ5ry0Rh3tSgO7ClqKswY8m8r28SqSXyd7zsXm0NZmk='
    keypair = ed25519.crypto_sign_keypair( dominion_sigkey[:32] )
    assert keypair.sk == dominion_sigkey
    assert lic.author_pubkey == b'\xa9\x91\x11\x9e0\xd9e9\xa7\x0c\xd3I\x83\xdd\x00qBY\xf8\xb6\n!c\xbd\xb7H\xf3\xfc\x0c\xf06\xc9'
    assert codecs.getencoder( 'base64' )( keypair.vk ) == (b'qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk=\n', 32)
    #print("ed25519 keypair: {sk}".format( sk=binascii.hexlify( keypair.sk )))
    prov = LicenseSigned( lic, keypair.sk )

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
        "product":"Cpppo Test",
        "start":"2021-09-30 17:22:33 UTC"
    },
    "signature":"67kACxXGVDfuJS+uuV8xDvMPjtORzTZ8WO18biDqPO6KUvZNrONGBjvDyx5fOnzPQSS/O+HP946XSLOxoi0PDg=="
}"""
    # Multiple licenses, some which truncate the duration of the initial License. Non-timezone
    # timestamps are assumed to be UTC.
    start, length = lic.overlap(
        License( author = "A", product = 'a', author_domain='a-inc.com', author_pubkey=keypair.vk, start = "2021-09-29 00:00:00", length = "1w" ),
        License( author = "B", product = 'b', author_domain='b-inc.com', author_pubkey=keypair.vk, start = "2021-09-30 00:00:00", length = "1w" ))
    # Default rendering of a timestamp is w/ milliseconds, and no tz info for UTC
    assert str( start ) == "2021-09-30 17:22:33.000"
    assert str( length ) == "5d6h37m27s"

    # Attempt to find overlap between non-overlapping Licenses.  Uses the local timezone for
    # rendering; force by setting environment variable TZ=Canada/Mountain for this test!
    with pytest.raises( LicenseIncompatibility ) as exc_info:
        start, length = lic.overlap(
            License( author = "A", product = 'a', author_domain='a-inc.com', author_pubkey=keypair.vk, start = "2021-09-29 00:00:00", length = "1w" ),
            License( author = "B", product = 'b', author_domain='b-inc.com', author_pubkey=keypair.vk, start = "2021-10-07 00:00:00", length = "1w" ))
    assert str( exc_info.value ).endswith( "License for B's 'b' (2021-10-06 18:00:00 Canada/Mountain for 1w) incompatible with others (2021-09-30 11:22:33 Canada/Mountain for 5d6h37m27s)" )


def test_LicenseSigned():
    """Tests Licenses derived from other License dependencies."""
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
    # Obtain a signed Cpppo license for 2021-09-30 + 1y
    lic_prov = issue( lic, dominion_sigkey )

    # Create a signing key for Awesome, Inc.; securely hide it, and publish the base-64 encoded public key as a TXT RR at:
    # ethernet-ip-tool.cpppo-licensing._domainkey.awesome.com 300 IN TXT "v=DKIM1; k=ed25519; p=

    awesome_keypair = author( seed=awesome_sigkey[:32] )

    print("Awesome, Inc. ed25519 keypair; Signing: {sk}".format( sk=binascii.hexlify( awesome_keypair.sk )))
    print("Awesome, Inc. ed25519 keypair; Public:  {pk}".format( pk=into_b64( awesome_keypair.vk )))

    # Almost at the end of their Cpppo license, they issue a new License.
    drv = License(
        author	= "Awesome, Inc.",
        product	= "EtherNet/IP Tool",
        author_domain = "awesome-inc.com",
        author_pubkey = awesome_keypair.vk, # Avoid the dns.resolver.NXDOMAIN by providing the pubkey
        dependencies = [ lic_prov ],
        start	= "2022-09-29 11:22:33 Canada/Mountain",
        length	= "1y",
        confirm = False,
    )
    drv_prov = issue( drv, awesome_keypair.sk )
    drv_prov_str = str( drv_prov )
    assert drv_prov_str == """\
{
    "license":{
        "author":"Awesome, Inc.",
        "author_domain":"awesome-inc.com",
        "author_pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
        "author_service":"ethernet-ip-tool",
        "client":null,
        "client_pubkey":null,
        "dependencies":[
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
                    "product":"Cpppo Test",
                    "start":"2021-09-30 17:22:33 UTC"
                },
                "signature":"67kACxXGVDfuJS+uuV8xDvMPjtORzTZ8WO18biDqPO6KUvZNrONGBjvDyx5fOnzPQSS/O+HP946XSLOxoi0PDg=="
            }
        ],
        "length":"1y",
        "product":"EtherNet/IP Tool",
        "start":"2022-09-29 17:22:33 UTC"
    },
    "signature":"2cGLHbL9DZ4YYOfhLJ0e0xpOhGxbw7TEVCpwKYtQaj2Pv9UfElfsXQgKlFqBYzjtq4tJIZKpfsQfwlOz9v9/BQ=="
}"""
