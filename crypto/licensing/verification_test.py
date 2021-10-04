import binascii
import pytest

from .verification import License, LicenseProvenance, LicenseIncompatibility
from .. import ed25519ll as ed25519

def test_License():
    lic = License(
        author	= "Dominion Research & Development Corp.",
        product	= "Cpppo",
        start	= "2021-09-30 11:22:33 Canada/Mountain",
        length	= "1y" )
    lic_str = str( lic )
    assert lic_str == """{"author": "Dominion Research & Development Corp.", "dependencies": "None", "length": "1y", "product": "Cpppo", "start": "2021-09-30 17:22:33 UTC"}"""

    assert lic.digest() == b'\xc1\xcaJ8QiS\xe0\xe3&w\xde%X\xe0\xcd\x96@\xa6!\xb9\xf7?\x9a\xc0\xe1\xe4@Wu\xd2\\'
    assert lic.hexdigest() == 'c1ca4a38516953e0e32677de2558e0cd9640a621b9f73f9ac0e1e4405775d25c'
    signer = binascii.unhexlify( '431f3fb4339144cb5bdeb77db3148a5d340269fa3bc0bf2bf598ce0625750fdca991119e30d96539a70cd34983dd00714259f8b60a2163bdb748f3fc0cf036c9' )
    keypair = ed25519.crypto_sign_keypair( signer[:32] )
    assert keypair.sk == signer
    #print("ed25519 keypair: {sk}".format( sk=binascii.hexlify( keypair.sk )))
    prov = LicenseProvenance( lic, keypair.sk )

    prov_str = str( prov )
    assert prov_str == """{"license": "{\\"author\\": \\"Dominion Research & Development Corp.\\", \\"dependencies\\": \\"None\\", \\"length\\": \\"1y\\", \\"product\\": \\"Cpppo\\", \\"start\\": \\"2021-09-30 17:22:33 UTC\\"}", "license_digest": "c1ca4a38516953e0e32677de2558e0cd9640a621b9f73f9ac0e1e4405775d25c", "signature": "8bb577e5877e1189b2c93daf6253d4be064417f180afc8f5cf4b9e533464c50bafe2b2029395e4d2cbf61e8ee391d236b38626d3d4e27f6b20028f252d81c008"}"""

    # Multiple licenses, some which truncate the duration of the initial License. Non-timezone
    # timestamps are assumed to be UTC.
    start, length = lic.overlap(
        License( author = "A", product = 'a', start = "2021-09-29 00:00:00", length = "1w" ),
        License( author = "B", product = 'b', start = "2021-09-30 00:00:00", length = "1w" ))
    # Default rendering of a timestamp is w/ milliseconds, and no tz info for UTC
    assert str( start ) == "2021-09-30 17:22:33.000"
    assert str( length ) == "5d6h37m27s"

    # Attempt to find overlap between non-overlapping Licenses.  Uses the local timezone for
    # rendering; force by setting environment variable TZ=Canada/Mountain for this test!
    with pytest.raises( LicenseIncompatibility ) as exc_info:
        start, length = lic.overlap(
            License( author = "A", product = 'a', start = "2021-09-29 00:00:00", length = "1w" ),
            License( author = "B", product = 'b', start = "2021-10-07 00:00:00", length = "1w" ))
    assert str( exc_info.value ).endswith( "License for B's 'b' (2021-10-06 18:00:00 Canada/Mountain for 1w) incompatible with others (2021-09-30 11:22:33 Canada/Mountain for 5d6h37m27s)" )
