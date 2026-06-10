from __future__ import absolute_import, print_function, division

import io
import json
import struct

from ...automata import dfa, state
from ...dotdict import dotdict
from . import device
from . import parser


TYPE_IS_STRUCT = 0x8000
TYPE_IS_ARRAY = 0x2000

GET_INSTANCE_ATTRIBUTE_LIST_REQ = 0x55
GET_INSTANCE_ATTRIBUTE_LIST_RPY = GET_INSTANCE_ATTRIBUTE_LIST_REQ | 0x80
GET_INSTANCE_ATTRIBUTE_LIST_CTX = "get_instance_attribute_list"
READ_TEMPLATE_REQ = 0x4C
READ_TEMPLATE_RPY = READ_TEMPLATE_REQ | 0x80

try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)

_registry = None


class ControllerTag(object):
    def __init__(self, instance_id, name, template_id, size, dimensions=None):
        self.instance_id = instance_id
        self.name = name
        self.template_id = template_id
        self.size = size
        self.dimensions = (dimensions or [0, 0, 0])[:3]
        while len(self.dimensions) < 3:
            self.dimensions.append(0)
        self.type_code = TYPE_IS_STRUCT | template_id


class UdtDefinition(object):
    def __init__(self, template_id, name, size, fields):
        self.template_id = template_id
        self.name = name
        self.size = size
        self.fields = fields


class UdtField(object):
    def __init__(self, name, type_code, offset, metadata=0, template_id=None, atomic_type=None, bit=None):
        self.name = name
        self.type_code = type_code
        self.offset = offset
        self.metadata = metadata
        self.template_id = template_id
        self.atomic_type = atomic_type
        self.bit = bit

    @property
    def is_struct(self):
        return (self.type_code & TYPE_IS_STRUCT) != 0 and self.template_id is not None

    @property
    def is_array(self):
        return (self.type_code & TYPE_IS_ARRAY) != 0


class RawStructParser(parser.STRUCT):
    def __init__(self, structure_tag, size):
        self.structure_tag = structure_tag
        self.struct_calcsize = size
        super(RawStructParser, self).__init__(structure_tag=structure_tag)


class BackingBuffer(object):
    def __init__(self, size):
        self.data = bytearray(size)

    def read(self, offset, size):
        return bytes(self.data[offset:offset + size])

    def write(self, offset, payload):
        end = offset + len(payload)
        assert end <= len(self.data)
        self.data[offset:end] = bytearray(payload)

    def read_values(self, offset, count, type_cls):
        type_parser = type_cls()
        size = type_parser.struct_calcsize
        fmt = type_parser.struct_format
        return [
            struct.unpack_from(fmt, self.data, offset + (index * size))[0]
            for index in range(count)
        ]

    def write_values(self, offset, values, type_cls):
        type_parser = type_cls()
        size = type_parser.struct_calcsize
        fmt = type_parser.struct_format
        for index, value in enumerate(values):
            struct.pack_into(fmt, self.data, offset + (index * size), value)

    def read_bit(self, offset, bit):
        return bool(self.data[offset] & (1 << bit))

    def write_bit(self, offset, bit, value):
        if value:
            self.data[offset] |= 1 << bit
        else:
            self.data[offset] &= ~(1 << bit)


class StructSliceAttribute(object):
    error = 0x00

    def __init__(self, name, backing, offset, size, structure_tag):
        self.name = name
        self.backing = backing
        self.offset = offset
        self.size = size
        self.parser = RawStructParser(structure_tag=structure_tag, size=size)

    def __len__(self):
        return 1

    def __getitem__(self, key):
        self._validate_key(key)
        record = dotdict()
        record.data = dotdict()
        record.data.input = self.backing.read(self.offset, self.size)
        return [record] if isinstance(key, slice) else record

    def __setitem__(self, key, value):
        self._validate_key(key)
        payload = self._coerce_payload(value)
        self.backing.write(self.offset, payload[:self.size])

    def _validate_key(self, key):
        if isinstance(key, slice):
            start, stop, stride = key.indices(1)
            if start == 0 and stop == 1 and stride == 1:
                return
        elif key == 0:
            return
        raise KeyError("Unsupported STRUCT slice for {0}: {1!r}".format(self.name, key))

    def _coerce_payload(self, value):
        if isinstance(value, list):
            value = value[0]
        if hasattr(value, "input"):
            return bytes(bytearray(value.input))
        if hasattr(value, "data") and hasattr(value.data, "input"):
            return bytes(bytearray(value.data.input))
        return bytes(bytearray(value))


class AtomicArrayAttribute(object):
    error = 0x00

    def __init__(self, name, backing, offset, count, type_cls):
        self.name = name
        self.backing = backing
        self.offset = offset
        self.count = count
        self.type_cls = type_cls
        self.parser = type_cls()

    def __len__(self):
        return self.count

    def __getitem__(self, key):
        values = self.backing.read_values(self.offset, self.count, self.type_cls)
        return values[key]

    def __setitem__(self, key, value):
        values = self.backing.read_values(self.offset, self.count, self.type_cls)
        if isinstance(key, slice):
            values[key] = list(value)
        else:
            values[key] = value
        self.backing.write_values(self.offset, values, self.type_cls)


class BoolAttribute(object):
    error = 0x00

    def __init__(self, name, backing, offset, bit):
        self.name = name
        self.backing = backing
        self.offset = offset
        self.bit = bit
        self.parser = parser.BOOL()

    def __len__(self):
        return 1

    def __getitem__(self, key):
        self._validate_key(key)
        value = self.backing.read_bit(self.offset, self.bit)
        return [value] if isinstance(key, slice) else value

    def __setitem__(self, key, value):
        self._validate_key(key)
        if isinstance(key, slice):
            value = next(iter(value))
        self.backing.write_bit(self.offset, self.bit, bool(value))

    def _validate_key(self, key):
        if isinstance(key, slice):
            start, stop, stride = key.indices(1)
            if start == 0 and stop == 1 and stride == 1:
                return
        elif key == 0:
            return
        raise KeyError("Unsupported BOOL slice for {0}: {1!r}".format(self.name, key))


class BytesAttribute(object):
    error = 0x00

    def __init__(self, name, payload):
        self.name = name
        self.payload = list(bytearray(payload))
        self.parser = parser.USINT()

    def __len__(self):
        return len(self.payload)

    def __getitem__(self, key):
        return self.payload[key]

    def __setitem__(self, key, value):
        self.payload[key] = value


class DefinedTagsRegistry(object):
    def __init__(self, controller_tags, templates):
        self.controller_tags = controller_tags
        self.templates = templates

    @classmethod
    def from_file(cls, path):
        with io.open(path, "r", encoding="utf-8") as schema_file:
            return cls.from_dict(json.load(schema_file))

    @classmethod
    def from_json(cls, text):
        return cls.from_dict(json.loads(text))

    @classmethod
    def from_source(cls, source):
        if _looks_like_json_text(source):
            return cls.from_json(source)
        return cls.from_file(source)

    @classmethod
    def from_dict(cls, schema):
        templates = _parse_templates(schema["templates"])
        controller_tags = [
            ControllerTag(
                _as_int(item.get("id", index + 1)),
                item["name"],
                _as_int(item.get("templateId", item.get("typeTemplateId"))),
                _as_int(item["size"]),
                [_as_int(value) for value in item.get("dimensions", [0, 0, 0])],
            )
            for index, item in enumerate(schema["controllerTags"])
        ]
        return cls(controller_tags, templates)

    def build_tags(self):
        tags = dotdict()
        for controller_tag in self.controller_tags:
            backing = BackingBuffer(controller_tag.size)
            root_template = self.templates[controller_tag.template_id]
            self._add_struct_tag(
                tags,
                controller_tag.name,
                controller_tag.name,
                backing,
                0,
                controller_tag.size,
                controller_tag.template_id,
            )
            self._add_template_members(tags, controller_tag.name, backing, 0, root_template, {})

        _add_tag(tags, "@tags", BytesAttribute("@tags", self.build_tag_listing_payload()))
        for template_id in self.templates:
            _add_tag(tags, "@udt/{0}".format(template_id), BytesAttribute(
                "@udt/{0}".format(template_id),
                self.build_udt_payload(template_id),
            ))
        return tags

    def build_tag_listing_payload(self):
        payload = bytearray()
        for controller_tag in self.controller_tags:
            payload += _tag_info_record(
                controller_tag.instance_id,
                controller_tag.type_code,
                controller_tag.size,
                controller_tag.dimensions,
                controller_tag.name,
            )
        return bytes(payload)

    def build_udt_payload(self, template_id):
        definition = self.templates[int(template_id)]
        payload = bytearray()
        payload += struct.pack(
            "<HIIHH",
            definition.template_id,
            len(definition.fields) * 8,
            definition.size,
            len(definition.fields),
            definition.template_id,
        )
        for field in definition.fields:
            payload += struct.pack("<HHI", field.metadata, field.type_code, field.offset)
        payload += _cstring(definition.name)
        for field in definition.fields:
            payload += _cstring(field.name)
        return bytes(payload)

    def template_attribute_list_payload(self, template_id, requested_attributes):
        definition = self.templates[int(template_id)]
        values = {
            1: struct.pack("<H", definition.template_id),
            2: struct.pack("<H", len(definition.fields)),
            4: struct.pack("<I", self.template_definition_words(template_id)),
            5: struct.pack("<I", definition.size),
        }

        payload = bytearray()
        payload += struct.pack("<H", len(requested_attributes))
        for attribute_id in requested_attributes:
            payload += struct.pack("<H", attribute_id)
            if attribute_id in values:
                payload += struct.pack("<H", 0)
                payload += values[attribute_id]
            else:
                payload += struct.pack("<H", 0x14)
        return bytes(payload)

    def template_read_payload(self, template_id):
        body = self.build_udt_payload(template_id)[14:]
        requested_size = (self.template_definition_words(template_id) * 4) - 23
        return body + (b"\x00" * max(0, requested_size - len(body)))

    def template_definition_words(self, template_id):
        body_size = len(self.build_udt_payload(template_id)) - 14
        return (body_size + 23 + 3) // 4

    def register_objects(self):
        _register_get_instance_attribute_list_parser()
        if device.lookup(DefinedSymbolObject.class_id, 0) is None:
            DefinedSymbolObject(name="Defined Tag Symbol Object", instance_id=0)
        for template_id in self.templates:
            if device.lookup(DefinedTemplateObject.class_id, template_id) is None:
                DefinedTemplateObject(
                    name="Defined Tag Template {0}".format(template_id),
                    instance_id=template_id,
                )

    def _add_template_members(self, tags, parent_path, backing, base_offset, template, bit_counters):
        for field in template.fields:
            path = parent_path + "." + field.name
            offset = base_offset + field.offset
            if field.is_struct:
                nested_template = self.templates[field.template_id]
                self._add_struct_tag(tags, path, field.name, backing, offset, nested_template.size, field.template_id)
                self._add_template_members(tags, path, backing, offset, nested_template, bit_counters)
            elif field.atomic_type == "BOOL":
                if field.bit is None:
                    bit = bit_counters.get(offset, 0)
                else:
                    bit = field.bit
                bit_counters[offset] = max(bit_counters.get(offset, 0), bit + 1)
                _add_tag(tags, path, BoolAttribute(field.name, backing, offset, bit))
            else:
                count = field.metadata if field.is_array else 1
                _add_tag(tags, path, AtomicArrayAttribute(
                    field.name,
                    backing,
                    offset,
                    count,
                    _atomic_type_class(field.atomic_type),
                ))

    def _add_struct_tag(self, tags, path, name, backing, offset, size, template_id):
        _add_tag(tags, path, StructSliceAttribute(name, backing, offset, size, template_id))


class DefinedSymbolObject(device.Object):
    class_id = 0x6B

    def request(self, data, addr=None):
        registry = current_registry()
        if registry and (data.get("service") == GET_INSTANCE_ATTRIBUTE_LIST_REQ
                         or GET_INSTANCE_ATTRIBUTE_LIST_CTX in data):
            data.service = GET_INSTANCE_ATTRIBUTE_LIST_RPY
            data.status = 0x00
            data.pop("status_ext", None)
            data.input = bytearray(
                _octets([data.service, 0x00, data.status, 0x00])
                + registry.build_tag_listing_payload()
            )
            return True

        return super(DefinedSymbolObject, self).request(data, addr=addr)


class DefinedTemplateObject(device.Object):
    class_id = 0x6C

    def request(self, data, addr=None):
        registry = current_registry()
        if not registry or self.instance_id not in registry.templates:
            return super(DefinedTemplateObject, self).request(data, addr=addr)

        if data.get("service") == device.Object.GA_LST_REQ:
            payload = registry.template_attribute_list_payload(self.instance_id, data.get_attribute_list)
            data.service = device.Object.GA_LST_RPY
            data.status = 0x00
            data.pop("status_ext", None)
            data.input = bytearray(_octets([data.service, 0x00, data.status, 0x00]) + payload)
            return True

        if data.get("service") == READ_TEMPLATE_REQ:
            payload = registry.template_read_payload(self.instance_id)
            data.service = READ_TEMPLATE_RPY
            data.status = 0x00
            data.pop("status_ext", None)
            data.input = bytearray(_octets([data.service, 0x00, data.status, 0x00]) + payload)
            return True

        return super(DefinedTemplateObject, self).request(data, addr=addr)


def load_defined_tags_file(path):
    global _registry
    _registry = DefinedTagsRegistry.from_file(path)
    return _registry


def load_defined_tags(source):
    global _registry
    _registry = DefinedTagsRegistry.from_source(source)
    return _registry


def configure_defined_tags(schema):
    global _registry
    _registry = DefinedTagsRegistry.from_dict(schema)
    return _registry


def current_registry():
    return _registry


def reset_defined_tags():
    global _registry
    _registry = None


def register_defined_tags(target_tags):
    if not _registry:
        return target_tags

    _registry.register_objects()
    defined_tags = _registry.build_tags()
    for key, value in dict.items(defined_tags):
        dict.__setitem__(target_tags, key, value)
    return target_tags


def _parse_templates(items):
    templates = {}
    for item in items:
        template_id = _as_int(item["id"])
        fields = []
        for field in item.get("fields", []):
            fields.append(_parse_field(field))
        templates[template_id] = UdtDefinition(template_id, item["name"], _as_int(item["size"]), fields)
    return templates


def _parse_field(field):
    explicit = field.get("typeCode")
    template_id = field.get("templateId")
    atomic_type = None
    metadata = field.get("metadata", field.get("arrayLength", 0))
    type_name = field.get("type")
    type_name = type_name.upper() if type_name is not None else None

    if explicit is not None:
        type_code = _as_int(explicit)
        if "arrayLength" in field or field.get("array", False):
            type_code |= TYPE_IS_ARRAY
        if type_code & TYPE_IS_STRUCT:
            if template_id is None:
                template_id = type_code & ~(TYPE_IS_STRUCT | TYPE_IS_ARRAY)
        elif type_name and type_name not in ("UDT", "STRUCT"):
            atomic_type = type_name
        else:
            atomic_type = _atomic_type_name_from_type_code(type_code)
    else:
        if type_name in ("UDT", "STRUCT"):
            template_id = _as_int(template_id)
            type_code = TYPE_IS_STRUCT | template_id
        else:
            atomic_type = type_name
            type_code = _atomic_type_class(atomic_type).tag_type
            if "arrayLength" in field or field.get("array", False):
                type_code |= TYPE_IS_ARRAY

    return UdtField(
        field["name"],
        type_code,
        _as_int(field["offset"]),
        _as_int(metadata or 0),
        _as_int(template_id) if template_id is not None else None,
        atomic_type,
        _as_int(field["bit"]) if "bit" in field else None,
    )


def _register_get_instance_attribute_list_parser():
    if GET_INSTANCE_ATTRIBUTE_LIST_REQ in device.Object.service:
        return

    srvc = parser.USINT(context="service")
    srvc[True] = path = parser.EPATH(context="path")
    path[None] = numr = parser.UINT(
        "number",
        context=GET_INSTANCE_ATTRIBUTE_LIST_CTX,
        extension=".number",
    )

    attr = parser.UINT(
        "attr",
        context=GET_INSTANCE_ATTRIBUTE_LIST_CTX,
        extension=".UINT",
    )
    attr[None] = parser.move_if(
        "attr",
        source="." + GET_INSTANCE_ATTRIBUTE_LIST_CTX + ".UINT",
        destination=GET_INSTANCE_ATTRIBUTE_LIST_CTX + ".attributes",
        initializer=lambda **kwds: [],
    )
    attr[None] = state("attr", terminal=True)

    numr[True] = attrs = dfa(
        "attributes",
        initial=attr,
        repeat="." + GET_INSTANCE_ATTRIBUTE_LIST_CTX + ".number",
    )
    attrs[None] = done = parser.octets_noop("done", terminal=True)
    done.initial[None] = parser.move_if(
        "move",
        source="." + GET_INSTANCE_ATTRIBUTE_LIST_CTX + ".attributes",
        destination=GET_INSTANCE_ATTRIBUTE_LIST_CTX,
        initializer=lambda **kwds: [],
    )

    device.Object.register_service_parser(
        number=GET_INSTANCE_ATTRIBUTE_LIST_REQ,
        name="Get Instance Attribute List",
        short=GET_INSTANCE_ATTRIBUTE_LIST_CTX,
        machine=srvc,
    )


def _atomic_types():
    return {
        "BOOL": parser.BOOL,
        "SINT": parser.SINT,
        "USINT": parser.USINT,
        "INT": parser.INT,
        "UINT": parser.UINT,
        "DINT": parser.DINT,
        "UDINT": parser.UDINT,
        "LINT": parser.LINT,
        "ULINT": parser.ULINT,
        "REAL": parser.REAL,
        "LREAL": parser.LREAL,
    }


def _atomic_type_class(type_name):
    atomic = _atomic_types()
    if type_name not in atomic:
        raise ValueError("Unsupported defined tag type: {0}".format(type_name))
    return atomic[type_name]


def _atomic_type_name_from_type_code(type_code):
    base_type_code = type_code & ~TYPE_IS_ARRAY
    for type_name, type_cls in _atomic_types().items():
        if type_cls.tag_type == base_type_code:
            return type_name
    raise ValueError("Unsupported defined tag type code: 0x{0:04X}".format(type_code))


def _octets(values):
    return bytes(bytearray(values))


def _looks_like_json_text(value):
    if not isinstance(value, string_types):
        return False
    stripped = value.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _add_tag(tags, name, attribute):
    entry = dotdict()
    entry.attribute = attribute
    entry.path = None
    entry.error = 0x00
    dict.__setitem__(tags, name, entry)


def _tag_info_record(instance_id, type_code, length, dimensions, name):
    encoded_name = name.encode("ascii")
    return struct.pack(
        "<IHHIIIH",
        instance_id,
        type_code,
        length,
        dimensions[0],
        dimensions[1],
        dimensions[2],
        len(encoded_name),
    ) + encoded_name


def _cstring(value):
    return value.encode("ascii") + b"\x00"


def _as_int(value):
    if isinstance(value, string_types):
        return int(value, 0)
    return int(value)
