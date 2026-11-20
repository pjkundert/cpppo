"""Regression checks for EDS generation from a Class 1 adapter."""

from __future__ import absolute_import

from datetime import datetime

import pytest

from ...dotdict import dotdict
from . import class1, device, eds, logix, parser


@pytest.fixture
def configured_adapter( monkeypatch ):
    """Register an adapter with a fresh directory for the duration of the test.

    Args:
        monkeypatch: Restores the shared registry after the test.

    Yields:
        The Class 1 adapter registered with the local Connection Manager.
    """
    monkeypatch.setattr( device, 'directory', dotdict() )
    monkeypatch.setattr( device, 'symbol', {} )
    monkeypatch.setattr( logix.setup, 'ucmm', None )

    class Identity(device.Identity):
        """Test identity with distinct major and minor revisions."""

        def __init__( self, **kwds ):
            """Initialize test identity attributes.

            Args:
                **kwds: Standard CIP Identity constructor options.
            """
            super( Identity, self ).__init__( **kwds )
            if self.instance_id:
                for attr, value in (
                        ('1', 33), ('2', 43), ('3', 24),
                        ('4', 0x0207), ('7', 'EDS Unit Test'),
                ):
                    entry	= self.attribute[attr]
                    entry[0]	= value

    profile			= class1.InputOnly( 300, 301, 302, 6 )
    adapter			= class1.Adapter(
        profile, lambda: b'\0' * 6, ('127.0.0.1', 0),
    )
    try:
        logix.setup(
            class1_adapter	= adapter,
            identity_class	= Identity,
        )
        yield adapter
    finally:
        adapter.close()


def test_eds_from_registered_adapter( configured_adapter ):
    """Export the registered identity and 16-bit connection path.

    Args:
        configured_adapter: Initializes the local Identity and Adapter.
    """
    fields			= (
        eds.Field( 'Flags', parser.UINT ),
        eds.Field( 'Job ID', parser.UDINT ),
    )
    text			= eds.generate(
        fields	= fields,
        created	= datetime( 2026, 11, 19, 22, 45 ),
    )

    # Fields must describe the application size and retain their wire order.
    assert 'VendCode = 33;' in text and 'ProdCode = 24;' in text
    assert 'MajRev = 7;' in text and 'MinRev = 2;' in text
    assert '"20 04 25 00 2C 01 2D 00 2D 01 2D 00 2E 01";' in text
    assert 'Param1, 6, Assem302,' in text
    assert '16, Param2,\n        32, Param3;' in text
    assert '10000, 10000000, 50000,' in text
    assert '0x02010002, 0x44440305,' in text
    assert '48, ;' in eds.generate()


def test_eds_rejects_mismatched_layout( configured_adapter ):
    """Reject metadata that cannot describe the configured wire payload.

    Args:
        configured_adapter: Initializes the adapter and fixes its input size.
    """
    with pytest.raises( ValueError, match='fill the input assembly' ):
        eds.generate(
            configured_adapter,
            fields=(eds.Field( 'Flags', parser.UINT ),),
        )
