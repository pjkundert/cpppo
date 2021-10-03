import binascii

from .verification import License, LicenseProvenance
from .. import ed25519ll as ed25519

def test_License():
    lic = License(
        author	= "Dominion Research & Development Corp.",
        product	= "Cpppo",
        start	= "2021-09-30 11:22:33 Canada/Mountain",
        length	= "1y" )
    lic_str = str( lic )
    assert lic_str == """{"author": "Dominion Research & Development Corp.", "dependencies": "None", "length": "1y", "product": "Cpppo", "start": "2021-09-30 17:22:33.000"}"""

    assert lic.digest() == b'5\x8c\xa4\xdb\x82|n\x17\x12\xf8C\x8fD\xb6\xb0\xd6\xba\xf1&\x8a(\xd07\xc0\x04O\x1f\xdf\xa2\x19K\x1e'
    assert lic.hexdigest() == '358ca4db827c6e1712f8438f44b6b0d6baf1268a28d037c0044f1fdfa2194b1e'
    signer = binascii.unhexlify( '431f3fb4339144cb5bdeb77db3148a5d340269fa3bc0bf2bf598ce0625750fdca991119e30d96539a70cd34983dd00714259f8b60a2163bdb748f3fc0cf036c9' )
    keypair = ed25519.crypto_sign_keypair( signer[:32] )
    assert keypair.sk == signer
    print("ed25519 keypair: {sk}".format( sk=binascii.hexlify( keypair.sk )))
    prov = LicenseProvenance( lic, keypair.sk )

    prov_str = str( prov )
    assert prov_str == """{"license": "{\\"author\\": \\"Dominion Research & Development Corp.\\", \\"dependencies\\": \\"None\\", \\"length\\": \\"1y\\", \\"product\\": \\"Cpppo\\", \\"start\\": \\"2021-09-30 17:22:33.000\\"}", "license_digest": "358ca4db827c6e1712f8438f44b6b0d6baf1268a28d037c0044f1fdfa2194b1e", "signature": "6dfdd89a7cd1171a2b224db66817635f9ea23e25fbf6da76bf53822357dbf85d52d1619b59e820f0d4630e5e5d7eebbed72348e7d4f7c3af3b7ffab2372b800c"}"""
    
    start, length = lic.overlap(
        License( author = "A", product = 'a', start = "2021-09-29 00:00:00", length = "1w" ))
    assert str( start ) == "2021-09-30 17:22:33.000"
    assert str( length ) == "5d6h37m27s"
    
