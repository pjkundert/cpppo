
from .verification import License

def test_License():
    lic = License( author="Dominion Research & Development Corp.", product="Cpppo",
                   start="2021-09-30 11:22:33 Canada/Mountain", length="1y" )
    lic_str = str( lic )
    assert lic_str == """{"author": "Dominion Research & Development Corp.", "dependencies": "None", "length": "1y", "product": "Cpppo", "start": "2021-09-30 17:22:33.000"}"""
