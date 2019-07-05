# Note this implementation is more strict than necessary to demonstrate
# minimum restrictions on types allowed in dictionaries.

# For Python 2.7/3.3 compatibility, we deal in bytes only; encode/decode utf-8
# Python2/3 unicode/str before/after calling.

from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import sys

def dump(data, encoding='utf-8'):
    """Dump a Python data structure into a tnetstring.  All user-supplied non-bytes
    str data is encoded with the given encoding (required in Python3, unless all
    character data are supplied as bytes, and if unicode '$' format data is
    suppoed).  All internally generated numeric str data and dictionary keys
    must be simple 'ascii' encoded (non-multibyte, 7-bit clean)."""
    if type(data) in ((int,long) if sys.version_info[0] < 3 else (int,)):
        out = str(data).encode('ascii')
        typ = b'#'
    elif type(data) is float:
        out = str(data).encode('ascii')
        typ = b'^'
    elif type(data) is bytes: # =~= str in Python2, bytes in Python3
        out = data
        typ = b','
    elif type(data) is (unicode if sys.version_info[0] < 3 else str):
        # User-supplied non-bytes character data: must decode to bytes
        # according to supplied encoding (typically should be 'utf-8').
        out = data.encode(encoding) # u'...' in Python2, str in Python3
        typ = b'$'
    elif type(data) is bool:
        out = repr(data).lower().encode('ascii')
        typ = b'!'
    elif type(data) is dict:
        return dump_dict(data, encoding=encoding)
    elif type(data) in (list, tuple):
        return dump_list(data, encoding=encoding)
    elif data == None:
        return b'0:~'
    else:
        assert False, "Can't serialize stuff that's %s." % type(data)

    siz = ('%d' % len(out)).encode('ascii')
    return siz + b':' + out + typ

def parse(data, encoding='utf-8'):
    """If no encoding supplied, all character data in payload is returned as bytes.
    In Python2, this is equivalent to str; in Python3, the user must encode the
    data to the desired string encoding."""
    payload, payload_type, remain = parse_payload(data)

    if payload_type == b'#':
        value = int(payload)
    elif payload_type == b'}':
        value = parse_dict(payload, encoding=encoding)
    elif payload_type == b']':
        value = parse_list(payload, encoding=encoding)
    elif payload_type == b'!':
        value = payload == b'true'
    elif payload_type == b'?':
        assert len(payload) == 1
        value = payload == b't'
    elif payload_type == b'^':
        value = float(payload)
    elif payload_type == b'~':
        assert len(payload) == 0, "Payload must be 0 length for null."
        value = None
    elif payload_type == b',':
        value = payload # bytes =~= str in Python2
    elif payload_type == b'$':
        value = payload.decode(encoding)
    else:
        assert False, "Invalid payload type: %r" % payload_type

    return value, remain

def parse_payload(data):
    assert data, "Invalid data to parse, it's empty."
    assert type( data ) is bytes, "Only raw bytes data may be parsed"
    length, extra = data.split(b':', 1)
    length = int(length)

    payload, extra = extra[:length], extra[length:]
    assert extra, "No payload type: %r, %r" % (payload, extra)
    payload_type, remain = extra[0:1], extra[1:]

    assert len(payload) == length, "Data is wrong length %d vs %d" % (length, len(payload))
    return payload, payload_type, remain

def parse_list(data, encoding=None):
    result = []
    extra = data
    while extra:
        value, extra = parse(extra, encoding=encoding)
        result.append(value)

    return result

def parse_dict(data, encoding=None):
    result = {}
    extra = data
    while extra:
        key, extra = parse(extra)
        assert extra, "Unbalanced dictionary store."
        assert type(key) is bytes, "Keys can only be ascii-encoded character data, not %r: %r." % (
            type(key), key)
        value, extra = parse(extra, encoding=encoding)
        result[key.decode('ascii')] = value
  
    return result
    


def dump_dict(data, encoding=None):
    result = []
    for k,v in data.items():
        result.append(dump(str(k).encode('ascii')))
        result.append(dump(v,      encoding=encoding))

    payload = b''.join(result)
    return ('%d:' % len(payload)).encode('ascii') + payload + b'}'


def dump_list(data, encoding=None):
    payload = b''.join( dump(i, encoding=encoding) for i in data )
    return ('%d:' % len(payload)).encode('ascii') + payload + b']'


