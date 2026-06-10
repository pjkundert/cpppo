from __future__ import absolute_import, print_function, division

import json
import struct

from cpppo.server.enip import defined_tags
from cpppo.server.enip import device
from cpppo.server.enip import logix
from cpppo.server.enip import parser


SCHEMA = {
    "controllerTags": [
        {"id": 1, "name": "TestStruct", "templateId": 100, "size": 8},
    ],
    "templates": [
        {
            "id": 100,
            "name": "RootType",
            "size": 8,
            "fields": [
                {"name": "Flags", "type": "UDT", "templateId": 101, "offset": 0},
                {"name": "Values", "type": "INT", "arrayLength": 2, "offset": 4},
            ],
        },
        {
            "id": 101,
            "name": "FlagType",
            "size": 4,
            "fields": [
                {"name": "Raw0", "type": "SINT", "offset": 0},
                {"name": "Ready", "type": "BOOL", "offset": 0},
                {"name": "Fault", "type": "BOOL", "offset": 0},
                {"name": "Raw1", "type": "SINT", "offset": 1},
                {"name": "Reset", "type": "BOOL", "offset": 1},
            ],
        },
    ],
}


EXPLICIT_SCHEMA = {
    "controllerTags": [
        {"id": 1, "name": "ExplicitStruct", "templateId": 200, "size": 8},
    ],
    "templates": [
        {
            "id": 200,
            "name": "ExplicitRoot",
            "size": 8,
            "fields": [
                {"name": "Flags", "typeCode": "0x80C9", "offset": 0},
                {"name": "Values", "typeCode": "0x00C3", "arrayLength": 2, "offset": 4},
            ],
        },
        {
            "id": 201,
            "name": "ExplicitFlags",
            "size": 4,
            "fields": [
                {"name": "Raw0", "typeCode": "0x00C2", "offset": 0},
                {"name": "Ready", "typeCode": "0x00C1", "offset": 0, "bit": 3},
                {"name": "Fault", "type": "BOOL", "offset": 0},
            ],
        },
    ],
}


def test_defined_tags_registry_loads_utf8_json_file(tmpdir):
    schema_path = tmpdir.join("defined-tags.json")
    schema_path.write(json.dumps(EXPLICIT_SCHEMA))

    registry = defined_tags.DefinedTagsRegistry.from_file(str(schema_path))

    assert _decode_tag_records(registry.build_tag_listing_payload()) == [
        (1, 0x80C8, 8, (0, 0, 0), "ExplicitStruct"),
    ]
    assert _decode_template_fields(registry.build_udt_payload(200)) == [
        (0, 0x80C9, 0),
        (2, 0x20C3, 4),
    ]


def test_defined_tags_loader_accepts_json_text():
    try:
        registry = defined_tags.load_defined_tags(json.dumps(EXPLICIT_SCHEMA))

        assert registry is defined_tags.current_registry()
        assert _decode_tag_records(registry.build_tag_listing_payload()) == [
            (1, 0x80C8, 8, (0, 0, 0), "ExplicitStruct"),
        ]
        assert _decode_template_fields(registry.build_udt_payload(200)) == [
            (0, 0x80C9, 0),
            (2, 0x20C3, 4),
        ]
    finally:
        defined_tags.reset_defined_tags()


def test_defined_tags_listing_contains_configured_controller_tags():
    registry = _load_registry()
    payload = registry.build_tag_listing_payload()

    assert _decode_tag_records(payload) == [
        (1, 0x8064, 8, (0, 0, 0), "TestStruct"),
    ]


def test_defined_tags_udt_payload_contains_configured_shape():
    registry = _load_registry()

    assert _decode_template_header(registry.build_udt_payload(100)) == (100, 8, 2)
    assert _decode_template_fields(registry.build_udt_payload(100)) == [
        (0, 0x8065, 0),
        (2, 0x20C3, 4),
    ]
    assert _decode_template_header(registry.build_udt_payload(101)) == (101, 4, 5)
    assert _decode_template_fields(registry.build_udt_payload(101)) == [
        (0, 0x00C2, 0),
        (0, 0x00C1, 0),
        (0, 0x00C1, 0),
        (0, 0x00C2, 1),
        (0, 0x00C1, 1),
    ]


def test_defined_tags_buffered_attributes_share_one_payload():
    tags = _load_registry().build_tags()

    dict.__getitem__(tags, "TestStruct.Flags.Ready").attribute[0] = True
    dict.__getitem__(tags, "TestStruct.Flags.Fault").attribute[0] = True
    dict.__getitem__(tags, "TestStruct.Flags.Reset").attribute[0] = True
    dict.__getitem__(tags, "TestStruct.Values").attribute[0:2] = [10, -30]

    payload = _struct_payload(tags, "TestStruct")

    assert len(payload) == 8
    assert payload[0] == 0x03
    assert payload[1] == 0x01
    assert struct.unpack_from("<hh", payload, 4) == (10, -30)


def test_defined_tags_type_code_fields_and_explicit_bool_bits():
    registry = defined_tags.DefinedTagsRegistry.from_dict(EXPLICIT_SCHEMA)
    tags = registry.build_tags()

    dict.__getitem__(tags, "ExplicitStruct.Flags.Ready").attribute[0] = True
    dict.__getitem__(tags, "ExplicitStruct.Flags.Fault").attribute[0] = True
    dict.__getitem__(tags, "ExplicitStruct.Values").attribute[0:2] = [10, -30]

    payload = _struct_payload(tags, "ExplicitStruct")

    assert payload[0] == 0x18
    assert struct.unpack_from("<hh", payload, 4) == (10, -30)
    assert _decode_template_fields(registry.build_udt_payload(200)) == [
        (0, 0x80C9, 0),
        (2, 0x20C3, 4),
    ]


def test_defined_tags_struct_and_array_attribute_types_are_logix_compatible():
    tags = _load_registry().build_tags()

    assert dict.__getitem__(tags, "TestStruct").attribute.parser.tag_type == parser.STRUCT.tag_type
    assert dict.__getitem__(tags, "TestStruct").attribute.parser.structure_tag == 100
    assert dict.__getitem__(tags, "TestStruct.Flags").attribute.parser.structure_tag == 101
    assert dict.__getitem__(tags, "TestStruct.Values").attribute.parser.tag_type == parser.INT.tag_type
    assert len(dict.__getitem__(tags, "TestStruct.Values").attribute) == 2


def test_defined_tags_nested_tags_resolve_to_longest_registered_symbol():
    device.lookup_reset()
    logix.setup_reset()
    try:
        tags = _load_registry().build_tags()
        logix.setup(tags=tags)

        root = _resolve("TestStruct")
        flags = _resolve("TestStruct.Flags")
        ready = _resolve("TestStruct.Flags.Ready")

        assert root != flags
        assert flags != ready
    finally:
        defined_tags.reset_defined_tags()


def test_defined_tag_symbol_object_returns_tag_payload():
    device.lookup_reset()
    logix.setup_reset()
    try:
        registry = _configure_registry()
        registry.register_objects()

        symbol_object = device.lookup(defined_tags.DefinedSymbolObject.class_id, 0)
        request = _object_request(
            defined_tags.GET_INSTANCE_ATTRIBUTE_LIST_REQ,
            defined_tags.DefinedSymbolObject.class_id,
            0,
        )
        request[defined_tags.GET_INSTANCE_ATTRIBUTE_LIST_CTX] = [2, 7, 8, 1]

        assert symbol_object.request(request)
        assert bytes(request.input[:4]) == b"\xd5\x00\x00\x00"
        assert bytes(request.input[4:]) == registry.build_tag_listing_payload()
    finally:
        defined_tags.reset_defined_tags()


def test_defined_tag_template_object_returns_udt_attributes_and_template_body():
    device.lookup_reset()
    logix.setup_reset()
    try:
        registry = _configure_registry()
        registry.register_objects()

        template_object = device.lookup(defined_tags.DefinedTemplateObject.class_id, 100)
        attr_request = _object_request(device.Object.GA_LST_REQ, defined_tags.DefinedTemplateObject.class_id, 100)
        attr_request.get_attribute_list = [4, 5, 2, 1]

        assert template_object.request(attr_request)
        payload = bytes(attr_request.input)
        assert payload[:6] == b"\x83\x00\x00\x00\x04\x00"
        assert struct.unpack_from("<HHI", payload, 6)[0:2] == (4, 0)
        assert struct.unpack_from("<HHI", payload, 14) == (5, 0, 8)
        assert struct.unpack_from("<HHH", payload, 22) == (2, 0, 2)
        assert struct.unpack_from("<HHH", payload, 28) == (1, 0, 100)

        read_request = _object_request(defined_tags.READ_TEMPLATE_REQ, defined_tags.DefinedTemplateObject.class_id, 100)
        assert template_object.request(read_request)
        expected_body = registry.build_udt_payload(100)[14:]
        assert bytes(read_request.input[:4]) == b"\xcc\x00\x00\x00"
        assert bytes(read_request.input[4:4 + len(expected_body)]) == expected_body
    finally:
        defined_tags.reset_defined_tags()


def _load_registry():
    return defined_tags.DefinedTagsRegistry.from_dict(SCHEMA)


def _configure_registry():
    return defined_tags.configure_defined_tags(SCHEMA)


def _decode_tag_records(payload):
    records = []
    offset = 0
    while offset < len(payload):
        instance_id, tag_type, tag_length = struct.unpack_from("<IHH", payload, offset)
        dimensions = struct.unpack_from("<III", payload, offset + 8)
        name_length = struct.unpack_from("<H", payload, offset + 20)[0]
        name = payload[offset + 22:offset + 22 + name_length].decode("ascii")
        records.append((instance_id, tag_type, tag_length, dimensions, name))
        offset += 22 + name_length
    return records


def _decode_template_header(payload):
    template_id = struct.unpack_from("<H", payload, 0)[0]
    instance_size = struct.unpack_from("<I", payload, 6)[0]
    num_fields = struct.unpack_from("<H", payload, 10)[0]
    structure_handle = struct.unpack_from("<H", payload, 12)[0]

    assert template_id == structure_handle
    return template_id, instance_size, num_fields


def _decode_template_fields(payload):
    num_fields = struct.unpack_from("<H", payload, 10)[0]
    return [
        struct.unpack_from("<HHI", payload, 14 + (index * 8))
        for index in range(num_fields)
    ]


def _struct_payload(tags, tag_name):
    full_record = dict.__getitem__(tags, tag_name).attribute[0]
    return bytearray(full_record.data.input)


def _resolve(tag):
    return device.resolve(
        {"segment": [{"symbolic": part} for part in tag.split(".")]},
        attribute=True,
    )


def _object_request(service, class_id, instance_id):
    request = defined_tags.dotdict()
    request.service = service
    request.path = defined_tags.dotdict()
    request.path.segment = [
        defined_tags.dotdict({"class": class_id}),
        defined_tags.dotdict({"instance": instance_id}),
    ]
    return request
