import json
import multiprocessing
import os
import threading
import time

try:
    # Python 3 import
    import queue
except ImportError:
    # Python 2 import
    import Queue as queue

from collections import namedtuple
from multiprocessing.managers import BaseManager, NamespaceProxy, MakeProxyType


def test_managed_proxy():
    class Managed:
        pass

    class Holder:
        def __init__(self, managed):
            self.managed = managed


    BaseManager.register('M', Managed, MakeProxyType('M', ()))
    m = BaseManager()
    m.start()
    managed = m.M()

    BaseManager.register('H', Holder, NamespaceProxy)
    m = BaseManager()
    m.start()
    holder = m.H(managed)


Caller				= namedtuple( "Caller", ("PID", "TID") )

def caller():
    return Caller( os.getpid(),threading.current_thread().ident )


def mutate( d ):
    """Let's mutate a dict in a multiprocessing.Process environment, entering the details of which
    Process this is, and what its PID/TID are.  Then, output what the dictionary holds, from the
    perspective of this Process (assume it presents at least the Mapping interface).
    
    NOTE: In Python 2, this could be a locally defined method; Python 3 cannot serialize local
    methods.

    """
    p			= multiprocessing.current_process()
    d[repr(p)]		= caller()
    print( "{p!r}: {d}".format( p=p, d=json.dumps( dict( d ), indent=4 )))


class DictManager(BaseManager):
    pass


DictProxy = MakeProxyType('DictProxy', (
    '__getitem__', '__setitem__',  'keys'  # Mapping interface
))

shared			= dict()

def get_dict():
    global shared
    return shared


DictManager.register('get_dict', get_dict, DictProxy)


def run_server():
    # Start the manager server
    manager = DictManager(address=('localhost', 50000), authkey=b'password')
    server = manager.get_server()
    print("Server started")
    server.serve_forever()


def run_client():
    # Connect to the manager server
    manager = DictManager(address=('localhost', 50000), authkey=b'password')
    manager.connect()

    # Get the proxy to the dictionary
    d = manager.get_dict()

    # Use the proxy to interact with the dictionary
    mutate( d )
    

def test_dict_proxy_implicit():
    """ """
    server_process = multiprocessing.Process(target=run_server)
    server_process.start()

    # Give the server a moment to start
    time.sleep(1)

    # Start the client
    run_client()
    ps				= list( multiprocessing.Process( target=run_client ) for _ in range( 10 ))
    for p in ps:
        p.start()
    for p in ps:
        p.join()

    # Terminate the server process
    server_process.terminate()


def test_dict_proxy_via_args():
    """Simplest test of a multiprocessing manager.dict() shared with several Process instances.  The
    dict proxy should be serialized and forwarded to the spawned Process instances, while all
    reads/writes are performed on the central manager.dict() instance.

    """
    with multiprocessing.Manager() as manager:
        d			= manager.dict()

        ps			= list( multiprocessing.Process( target=mutate, args=(d,) ) for _ in range( 10 ))
        for p in ps:
            p.start()
        for p in ps:
            p.join()

        print( json.dumps( dict( d ), indent=4 ))
        assert len(d) == 10  # 10 Process names
        assert len(set(p for p,_t in d.values() )) == 10  # 10 unique PIDs
#
# This module shows how to use arbitrary callables with a subclass of
# `BaseManager`.
#
# Copyright (c) 2006-2008, R Oudkerk
# All rights reserved.
#

from multiprocessing import freeze_support
from multiprocessing.managers import BaseManager, BaseProxy
import operator

##

class Foo(object):
    def f(self):
        print( 'you called Foo.f()' )
    def g(self):
        print( 'you called Foo.g()' )
    def _h(self):
        print( 'you called Foo._h()' )

# A simple generator function
def baz():
    for i in range(10):
        yield i*i

# Proxy type for generator objects
class GeneratorProxy(BaseProxy):
    _exposed_ = ('next', '__next__')
    def __iter__(self):
        return self
    def next(self):
        return self._callmethod('next')
    def __next__(self):
        return self._callmethod('__next__')

# Function to return the operator module
def get_operator_module():
    return operator

##

class MyManager(BaseManager):
    pass

# register the Foo class; make `f()` and `g()` accessible via proxy
MyManager.register('Foo1', Foo)

# register the Foo class; make `g()` and `_h()` accessible via proxy
MyManager.register('Foo2', Foo, exposed=('g', '_h'))

# register the generator function baz; use `GeneratorProxy` to make proxies
MyManager.register('baz', baz, proxytype=GeneratorProxy)

# register get_operator_module(); make public functions accessible via proxy
MyManager.register('operator', get_operator_module)

##

def test_multiprocessing_BaseManager():
    manager = MyManager()
    manager.start()

    print( '-' * 20 )

    f1 = manager.Foo1()
    f1.f()
    f1.g()
    assert not hasattr(f1, '_h')
    assert sorted(f1._exposed_) == sorted(['f', 'g'])

    print( '-' * 20 )

    f2 = manager.Foo2()
    f2.g()
    f2._h()
    assert not hasattr(f2, 'f')
    assert sorted(f2._exposed_) == sorted(['g', '_h'])

    print( '-' * 20 )

    it = manager.baz()
    for i in it:
        print( '<%d>' % i, )
    print

    print( '-' * 20 )

    op = manager.operator()
    print( 'op.add(23, 45) =', op.add(23, 45) )
    print( 'op.pow(2, 94) =', op.pow(2, 94) )
    print( 'op._exposed_ =', op._exposed_ )

if __name__ == '__main__':
    freeze_support()
    test_multiprocessing_BaseManager()
