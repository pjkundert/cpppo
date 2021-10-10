import binascii
import codecs
import pytest

from .verification import License, LicenseProvenance, LicenseIncompatibility
from .. import ed25519ll as ed25519

def test_License():
    lic = License(
        author	= "Dominion Research & Development Corp.",
        product	= "Cpppo Test",
        author_domain = "dominionrnd.com",
        start	= "2021-09-30 11:22:33 Canada/Mountain",
        length	= "1y" )
    lic_str = str( lic )
    assert lic_str == """\
{"author": "Dominion Research & Development Corp.", "author_domain": "dominionrnd.com", \
"author_pubkey": "a991119e30d96539a70cd34983dd00714259f8b60a2163bdb748f3fc0cf036c9", "author_service": "cpppo-test.cpppo-licensing", \
"client": null, "client_pubkey": null, "dependencies": null, "length": "1y", "product": "Cpppo Test", "start": "2021-09-30 17:22:33 UTC"}\
"""
    assert lic.digest() == b'\xd9#\x181D\xc5\x8e\xdcse14\xd9\xfe\xe6I\xc8\xe34[\x17\xa9\xa0\xe7#\x9eT%Fz2@'
    assert lic.digest('hex') == b'd923183144c58edc73653134d9fee649c8e3345b17a9a0e7239e5425467a3240'
    assert lic.digest('base64') == b'2SMYMUTFjtxzZTE02f7mScjjNFsXqaDnI55UJUZ6MkA=\n'
    signer = binascii.unhexlify( '431f3fb4339144cb5bdeb77db3148a5d340269fa3bc0bf2bf598ce0625750fdca991119e30d96539a70cd34983dd00714259f8b60a2163bdb748f3fc0cf036c9' )
    keypair = ed25519.crypto_sign_keypair( signer[:32] )
    assert keypair.sk == signer
    assert lic.author_pubkey == b'\xa9\x91\x11\x9e0\xd9e9\xa7\x0c\xd3I\x83\xdd\x00qBY\xf8\xb6\n!c\xbd\xb7H\xf3\xfc\x0c\xf06\xc9'
    assert codecs.getencoder( 'base64' )( keypair.vk ) == (b'qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk=\n', 32)
    #print("ed25519 keypair: {sk}".format( sk=binascii.hexlify( keypair.sk )))
    prov = LicenseProvenance( lic, keypair.sk )

    prov_str = str( prov )
    assert prov_str == """\
{\
"license": {"author": "Dominion Research & Development Corp.", "author_domain": "dominionrnd.com", \
"author_pubkey": "a991119e30d96539a70cd34983dd00714259f8b60a2163bdb748f3fc0cf036c9", "author_service": "cpppo-test.cpppo-licensing", \
"client": null, "client_pubkey": null, "dependencies": null, "length": "1y", "product": "Cpppo Test", "start": "2021-09-30 17:22:33 UTC"}, \
"signature": "146da29635ded1537f78a8a8a0e68410704bf9a2c89be01d7d57de8616ad7bda8744011a30c0af651fe2cf3b4a2c64fe891cf8decda540a495b25a4c237f7a02"\
}\
"""

    # Multiple licenses, some which truncate the duration of the initial License. Non-timezone
    # timestamps are assumed to be UTC.
    start, length = lic.overlap(
        License( author = "A", product = 'a', author_pubkey=keypair.vk, start = "2021-09-29 00:00:00", length = "1w" ),
        License( author = "B", product = 'b', author_pubkey=keypair.vk, start = "2021-09-30 00:00:00", length = "1w" ))
    # Default rendering of a timestamp is w/ milliseconds, and no tz info for UTC
    assert str( start ) == "2021-09-30 17:22:33.000"
    assert str( length ) == "5d6h37m27s"

    # Attempt to find overlap between non-overlapping Licenses.  Uses the local timezone for
    # rendering; force by setting environment variable TZ=Canada/Mountain for this test!
    with pytest.raises( LicenseIncompatibility ) as exc_info:
        start, length = lic.overlap(
            License( author = "A", product = 'a', author_pubkey=keypair.vk, start = "2021-09-29 00:00:00", length = "1w" ),
            License( author = "B", product = 'b', author_pubkey=keypair.vk, start = "2021-10-07 00:00:00", length = "1w" ))
    assert str( exc_info.value ).endswith( "License for B's 'b' (2021-10-06 18:00:00 Canada/Mountain for 1w) incompatible with others (2021-09-30 11:22:33 Canada/Mountain for 5d6h37m27s)" )
