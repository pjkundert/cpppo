"""Generate an Electronic Data Sheet for a cpppo Class 1 Input Only adapter."""

from __future__ import absolute_import

from datetime import datetime
from numbers import Integral

from ...misc import type_str_base
from . import class1, device, parser


DEFAULT_RPI_US			= 50000
_INTEGER_TYPES			= {
    parser.SINT: (-(1 << 7), (1 << 7) - 1),
    parser.INT: (-(1 << 15), (1 << 15) - 1),
    parser.DINT: (-(1 << 31), (1 << 31) - 1),
    parser.USINT: (0, (1 << 8) - 1),
    parser.UINT: (0, (1 << 16) - 1),
    parser.UDINT: (0, (1 << 32) - 1),
}
_INPUT_ONLY_CYCLIC_CLASS1	= 0x02010002
_FIXED_UNICAST_HEARTBEAT	= 0x44440305


def _quote( text ):
    """Quote a printable ASCII EDS string.

    Args:
        text: Value to encode as a string field.

    Returns:
        Text surrounded by quotes with embedded delimiters escaped.

    Raises:
        ValueError: The value is not printable ASCII.
    """
    if not isinstance( text, type_str_base ) or any(
            not ' ' <= character <= '~' for character in text ):
        raise ValueError( 'EDS text must be printable ASCII' )
    return '"{}"'.format( text.replace( '\\', '\\\\' ).replace( '"', '\\"' ) )


class Field(object):
    """Name and describe one whole-byte integer in a packed status assembly."""

    def __init__(
            self, name, cip_type, description='', units='',
            minimum=None, maximum=None, default=None,
    ):
        """Describe one member in wire order.

        Args:
            name: Display name for the member.
            cip_type: cpppo SINT, INT, DINT, USINT, UINT, or UDINT type.
            description: EDS help text.
            units: Engineering units, if applicable.
            minimum: Lower bound, defaulting to the CIP type's minimum.
            maximum: Upper bound, defaulting to the CIP type's maximum.
            default: Display default, using zero or the lower bound.

        Raises:
            ValueError: The type or bounds cannot represent this field.
        """
        if cip_type not in _INTEGER_TYPES:
            raise ValueError( 'EDS status fields require a fixed CIP integer' )
        low, high		= _INTEGER_TYPES[cip_type]
        self.minimum		= low if minimum is None else minimum
        self.maximum		= high if maximum is None else maximum
        if not (isinstance( self.minimum, Integral )
                and isinstance( self.maximum, Integral )):
            raise ValueError( 'EDS status field requires integer bounds' )
        if default is None:
            default		= max( self.minimum, min( 0, self.maximum ) )
        if (not isinstance( default, Integral )
                or not low <= self.minimum <= default <= self.maximum <= high):
            raise ValueError( 'EDS status field has invalid integer bounds' )
        self.default		= default
        self.name		= name
        self.cip_type		= cip_type
        self.description	= description
        self.units		= units


def _parameter( lines, number, field, read_only ):
    """Append one EDS parameter with an empty explicit link path.

    Args:
        lines: Output lines to extend.
        number: ParamN index.
        field: Member or RPI metadata.
        read_only: Whether the parameter describes produced I/O.
    """
    kind			= field.cip_type
    descriptor			= 0x0010 if read_only else 0
    lines.extend( [
        '    Param{} ='.format( number ),
        '        0, ,, 0x{:04X}, 0x{:02X}, {},'.format(
            descriptor, kind.tag_type, kind.struct_calcsize,
        ),
        '        {}, {}, {},'.format(
            _quote( field.name ), _quote( field.units ),
            _quote( field.description ),
        ),
        '        {:d}, {:d}, {:d},'.format(
            field.minimum, field.maximum, field.default,
        ),
        '        ,,,, ,,,, ;',
    ] )


def generate(
        adapter=None, identity=None, fields=(),
        vendor_name=None, product_type_name=None,
        catalog=None, home_url=None, created=None,
        assembly_name='Adapter Status', rpi_us=DEFAULT_RPI_US,
):
    """Render an ASCII EDS from the local adapter's identity and profile.

    A running cpppo server registers the Identity and Connection Manager.
    With no arguments, read those objects in the current process. The
    caller may also supply an InputOnly profile and Identity instance
    before starting the server. The callback that supplies cyclic bytes
    does not supply field names or types.

    Args:
        adapter: Live class1.Adapter, InputOnly profile, or None to look up
            the adapter registered with the local Connection Manager.
        identity: Identity instance, or None to use local instance 1.
        fields: Ordered Field values filling the entire input payload.
            An empty iterable describes the payload as a raw byte block.
        vendor_name: Human-readable vendor name.
        product_type_name: Human-readable CIP device type.
        catalog: Catalog identifier, if applicable.
        home_url: Product or documentation URL, if applicable.
        created: EDS creation timestamp as a datetime. Defaults to UTC now.
        assembly_name: Display name for the status assembly and connection.
        rpi_us: Default requested packet interval in microseconds.

    Returns:
        Complete EDS text for the fixed-size unicast Input Only profile.

    Raises:
        ValueError: The adapter, identity, fields, or RPI are unsupported.
    """
    if adapter is None:
        manager			= device.lookup( 0x06, 1 )
        adapter			= getattr( manager, 'class1_adapter', None )
    profile			= getattr( adapter, 'profile', adapter )
    if not isinstance( profile, class1.InputOnly ):
        raise ValueError( 'EDS generation requires an InputOnly profile' )
    if identity is None:
        identity		= device.lookup( 0x01, 1 )
    if not isinstance( identity, device.Identity ) or not identity.instance_id:
        raise ValueError( 'EDS generation requires an Identity instance' )
    if (not isinstance( rpi_us, Integral )
            or not class1.MIN_RPI_US <= rpi_us <= class1.MAX_RPI_US):
        raise ValueError( 'Default EDS RPI is outside the adapter range' )

    # Validate the optional layout against the configured wire size.
    fields			= tuple( fields )
    if any( not isinstance( field, Field ) for field in fields ):
        raise ValueError( 'EDS assembly metadata requires Field values' )
    size			= profile.input_size
    if fields and sum( f.cip_type.struct_calcsize for f in fields ) != size:
        raise ValueError( 'EDS field sizes must fill the input assembly' )

    vend, kind, code, rev, name	= (
        identity.attribute[str( number )][0] for number in (1, 2, 3, 4, 7)
    )
    if vendor_name is None:
        vendor_name		= 'Vendor {}'.format( vend )
    if created is None:
        created			= datetime.utcnow()
    # The forward path starts after the size byte in cpppo's EPATH encoding.
    encoded			= parser.EPATH.produce( profile.path )
    path_text			= ' '.join(
        '{:02X}'.format( byte ) for byte in bytearray( encoded[1:] )
    )

    lines			= [
        '$ Electronic Data Sheet for a cpppo Class 1 Input Only adapter.',
        '$ The product guide describes the explicit application interface.',
        '', '[File]',
        '    DescText = {};'.format( _quote( name ) ),
        '    CreateDate = {:%m-%d-%Y};'.format( created ),
        '    CreateTime = {:%H:%M:%S};'.format( created ),
        '    Revision = 1.0;',
    ]
    if home_url:
        lines.append( '    HomeURL = {};'.format( _quote( home_url ) ) )
    lines.extend( [
        '', '[Device]',
        '    VendCode = {};{}'.format(
            vend, '    $ Simulator placeholder' if vend == 0 else '',
        ),
        '    VendName = {};'.format( _quote( vendor_name ) ),
        '    ProdType = {};'.format( kind ),
        '    ProdCode = {};'.format( code ),
        '    MajRev = {};'.format( rev & 0xFF ),
        '    MinRev = {};'.format( (rev >> 8) & 0xFF ),
        '    ProdName = {};'.format( _quote( name ) ),
    ] )
    if product_type_name:
        lines.append( '    ProdTypeStr = {};'.format(
            _quote( product_type_name ),
        ) )
    if catalog:
        lines.append( '    Catalog = {};'.format( _quote( catalog ) ) )
    lines.extend( [
        '', '[Device Classification]', '    Class1 = EtherNetIP;',
        '', '[Params]',
    ] )
    rpi				= Field(
        'Requested Packet Interval', parser.UDINT,
        description	= 'RPI for both Class 1 directions',
        units		= 'us',
        minimum		= class1.MIN_RPI_US,
        maximum		= class1.MAX_RPI_US,
        default		= rpi_us,
    )
    _parameter( lines, 1, rpi, False )
    for number, field in enumerate( fields, start=2 ):
        _parameter( lines, number, field, True )

    # The assembly entry describes the bytes consumed by the scanner.
    # Leave its explicit path blank because this profile exposes cyclic I/O.
    point			= profile.path[3]['connection']
    assembly			= 'Assem{}'.format( point )
    members			= [
        '        {}, Param{}'.format( field.cip_type.struct_calcsize * 8, n )
        for n, field in enumerate( fields, start=2 )
    ] or ['        {}, '.format( size * 8 )]
    lines.extend( [
        '', '[Assembly]', '    {} ='.format( assembly ),
        '        {},'.format( _quote( assembly_name ) ),
        '        "", {}, 0x0000, ,,'.format( size ),
        ',\n'.join( members ) + ';',
        '', '[Connection Manager]',
        '    $ Class 1 cyclic Input Only. Both directions use fixed unicast.',
        '    Connection1 =',
        '        0x{:08X}, 0x{:08X},'.format(
            _INPUT_ONLY_CYCLIC_CLASS1, _FIXED_UNICAST_HEARTBEAT,
        ),
        '        Param1, 0, ,    $ O->T heartbeat, no application bytes',
        '        Param1, {}, {},    $ T->O modeless'.format( size, assembly ),
        '        , ,    $ Originator configuration',
        '        0, ,    $ Target configuration',
        '        {}, "",'.format( _quote( assembly_name + ' Input Only' ) ),
        '        {};'.format( _quote( path_text ) ),
        '', '[Capacity]',
        '    MaxIOProduceConsume = 1;',
        '    MaxIOMcastProducers = 0;',
        '    MaxIOMcastConsumers = 0;',
        '',
    ] )
    return '\n'.join( lines )
