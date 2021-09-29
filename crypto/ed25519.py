
# 
# Edward's Reference Python-only Implementation of ed25519 signatures
# 
# From https://ed25519.cr.yp.to/software.html
# Copyrights: The Ed25519 software is in the public domain.
#
# Minimal changes for Python2/3 compatibility by pjkundert
#

try: # pragma nocover
    unicode
    PY3 = False
    def asbytes(b):
        """Convert array of integers to byte string"""
        return ''.join(chr(x) for x in b)
    def joinbytes(b):
        """Convert array of bytes to byte string"""
        return ''.join(b)
    def bit(h, i):
        """Return i'th bit of bytestring h"""
        return (ord(h[i//8]) >> (i%8)) & 1

except NameError: # pragma nocover
    PY3 = True
    asbytes = bytes
    joinbytes = bytes
    def bit(h, i):
        return (h[i//8] >> (i%8)) & 1

import hashlib

b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

def H(m):
  return hashlib.sha512(m).digest()

def expmod(b,e,m):
  if e == 0: return 1
  t = expmod(b,e//2,m)**2 % m
  if e & 1: t = (t*b) % m
  return t

def inv(x):
  return expmod(x,q-2,q)

d = -121665 * inv(121666)
I = expmod(2,(q-1)//4,q)

def xrecover(y):
  xx = (y*y-1) * inv(d*y*y+1)
  x = expmod(xx,(q+3)//8,q)
  if (x*x - xx) % q != 0: x = (x*I) % q
  if x % 2 != 0: x = q-x
  return x

By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % q,By % q]

def edwards(P,Q):
  x1 = P[0]
  y1 = P[1]
  x2 = Q[0]
  y2 = Q[1]
  x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
  y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
  return [x3 % q,y3 % q]

def scalarmult(P,e):
  if e == 0: return [0,1]
  Q = scalarmult(P,e//2)
  Q = edwards(Q,Q)
  if e & 1: Q = edwards(Q,P)
  return Q

def encodeint(y):
  bits = [(y >> i) & 1 for i in range(b)]
  #return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b//8)])
  return asbytes([     sum([bits[i * 8 + j] << j for j in range(8)])  for i in range(b//8)])

def encodepoint(P):
  x = P[0]
  y = P[1]
  bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
  #return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b//8)])
  return asbytes([     sum([bits[i * 8 + j] << j for j in range(8)])  for i in range(b//8)])

def publickey(sk):
  h = H(sk)
  a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
  A = scalarmult(B,a)
  return encodepoint(A)

def Hint(m):
  h = H(m)
  return sum(2**i * bit(h,i) for i in range(2*b))

def signature(m,sk,pk):
  h = H(sk)
  a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
  #r = Hint(''.join([h[i] for i in range(b//8,b//4)]) + m)
  r = Hint(joinbytes( [h[i] for i in range(b//8,b//4)]) + m)
  R = scalarmult(B,r)
  S = (r + Hint(encodepoint(R) + pk + m) * a) % l
  return encodepoint(R) + encodeint(S)

def isoncurve(P):
  x = P[0]
  y = P[1]
  return (-x*x + y*y - 1 - d*x*x*y*y) % q == 0

def decodeint(s):
  return sum(2**i * bit(s,i) for i in range(0,b))

def decodepoint(s):
  y = sum(2**i * bit(s,i) for i in range(0,b-1))
  x = xrecover(y)
  if x & 1 != bit(s,b-1): x = q-x
  P = [x,y]
  if not isoncurve(P): raise Exception("decoding point that is not on curve")
  return P

def checkvalid(s,m,pk):
  if len(s) != b//4: raise Exception("signature length is wrong")
  if len(pk) != b//8: raise Exception("public-key length is wrong")
  R = decodepoint(s[0:b//8])
  A = decodepoint(pk)
  S = decodeint(s[b//8:b//4])
  h = Hint(encodepoint(R) + pk + m)
  if scalarmult(B,S) != edwards(R,scalarmult(A,h)):
    raise Exception("signature does not pass verification")


# Provide the ed25519ll API for compatibility

import warnings
import os

from collections import namedtuple

PUBLICKEYBYTES=32
SECRETKEYBYTES=64
SIGNATUREBYTES=64

Keypair = namedtuple('Keypair', ('vk', 'sk')) # verifying key, secret key

def crypto_sign_keypair(seed=None):
    """Return (verifying, secret) key from a given seed, or os.urandom(32)"""    
    if seed is None:
        seed = os.urandom(PUBLICKEYBYTES)
    else:
        warnings.warn("ed25519ll should choose random seed.",
                      RuntimeWarning)
    if len(seed) != 32:
        raise ValueError("seed must be 32 random bytes or None.")
    # XXX should seed be constrained to be less than 2**255-19?
    skbytes = seed
    vkbytes = publickey(skbytes)
    return Keypair(vkbytes, skbytes+vkbytes)


def crypto_sign(msg, sk):
    """Return signature+message given message and secret key.
    The signature is the first SIGNATUREBYTES bytes of the return value.
    A copy of msg is in the remainder."""
    if len(sk) != SECRETKEYBYTES:
        raise ValueError("Bad signing key length %d" % len(sk))
    vkbytes = sk[PUBLICKEYBYTES:]
    skbytes = sk[:PUBLICKEYBYTES]
    sig = signature(msg, skbytes, vkbytes)
    return sig + msg


def crypto_sign_open(signed, vk):
    """Return message given signature+message and the verifying key."""
    if len(vk) != PUBLICKEYBYTES:
        raise ValueError("Bad verifying key length %d" % len(vk))
    checkvalid(signed[:SIGNATUREBYTES], signed[SIGNATUREBYTES:], vk) # raises Exception on failure
    return signed[SIGNATUREBYTES:]

