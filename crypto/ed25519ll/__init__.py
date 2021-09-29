# -*- coding: utf-8 -*-

# From github.com/dholth/ed25519ll/ed25519ll (MIT licensed)
# Uses a pure Python implementation only.
# 
# To use a faster C implementation, install the Python ed25519ll package using one of:
# 
#    pip3 install ed25519ll
#    pip3 install git+https://github.com/pjkundert/ed25519ll.git@master
#    pip3 install -r requirements-optional-crypto.txt

import warnings
import os

from collections import namedtuple
from . import djbec

__all__ = ['crypto_sign', 'crypto_sign_open', 'crypto_sign_keypair', 'Keypair',
           'SEEDVALUEBYTES', 'PUBLICKEYBYTES', 'SECRETKEYBYTES', 'SIGNATUREBYTES']

SEEDVALUEBYTES=32
PUBLICKEYBYTES=32
SECRETKEYBYTES=64
SIGNATUREBYTES=64

Keypair = namedtuple('Keypair', ('vk', 'sk')) # verifying key, secret key

def crypto_sign_keypair(seed=None):
    """Return (verifying, secret) key from a given seed, or os.urandom(32), or re-confirm provided
    secret key.

    """
    if seed is None:
        seed = os.urandom(SEEDVALUEBYTES)
    else:
        warnings.warn("ed25519ll should choose a {}-byte random seed.".format( SEEDVALUEBYTES ),
                      RuntimeWarning)
    if len(seed) == SEEDVALUEBYTES:
        skbytes = seed
        vkbytes = djbec.publickey(skbytes)
    elif len(seed) == SECRETKEYBYTES:
        skbytes = seed[:SEEDVALUEBYTES]
        vkbytes = djbec.publickey(skbytes)
        if vkbytes != seed[SEEDVALUEBYTES:]:
            raise ValueError("Provided secret key did not contain expected public key")
    else:
        raise ValueError("seed must be 32-byte random value or None.")
    return Keypair(vkbytes, skbytes+vkbytes)


def crypto_sign(msg, sk):
    """Return signature+message given message and secret key.
    The signature is the first SIGNATUREBYTES bytes of the return value.
    A copy of msg is in the remainder."""
    if len(sk) != SECRETKEYBYTES:
        raise ValueError("Bad signing key length %d" % len(sk))
    vkbytes = sk[PUBLICKEYBYTES:]
    skbytes = sk[:PUBLICKEYBYTES]
    sig = djbec.signature(msg, skbytes, vkbytes)
    return sig + msg


def crypto_sign_open(signed, vk):
    """Return message given signature+message and the verifying key."""
    if len(vk) != PUBLICKEYBYTES:
        raise ValueError("Bad verifying key length %d" % len(vk))
    rc = djbec.checkvalid(signed[:SIGNATUREBYTES], signed[SIGNATUREBYTES:], vk)
    if not rc:
        raise ValueError("rc != 0", rc)    
    return signed[SIGNATUREBYTES:]

