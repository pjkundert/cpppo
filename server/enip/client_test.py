from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import json
import logging
import multiprocessing
import os
import random
import socket
import sys
import threading
import time
import traceback

if __name__ == "__main__":
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
    from cpppo.automata import log_cfg
    logging.basicConfig( **log_cfg )
    #logging.getLogger().setLevel( logging.INFO )

import cpppo
from   cpppo.server import enip, network
from   cpppo.server.enip import client

log				= logging.getLogger( "cli.test" )
#log.setLevel( logging.INFO )

def test_client_api():
    """Performance of executing an operation a number of times on a socket connected
    Logix simulator, within the same Python interpreter (ie. all on a single CPU
    thread).

    """
    # TODO: work in progress; not operational yet (only one clitest Thread)

    svraddr		        = ('localhost', 12346)
    svrkwds			= cpppo.dotdict({
        'argv': [
            #'-v',
            '--address',	'%s:%d' % svraddr,
            'Tag=DINT[1000]'
        ],
        'server': {
            'control':	cpppo.apidict( enip.timeout, { 
                'done': False
            }),
        },
    })

    def clitest( n ):
        times			= 100
        tags			= ["Tag[0-49]", "Tag[1]=1"]
        connection		= None
        while not connection:
            try:
                connection	= client.connector( *svraddr, timeout=5 )
            except ConnectionRefusedError:
                time.sleep( .1 )
        results			= []
        failures		= 0
        transactions		= 0
        with connection:
            for idx,dsc,req,rpy,sts,val in connection.pipeline( 
                    operations=client.parse_operations( client.recycle( tags, times=times )),
                    multiple=500, timeout=5, depth=3 ):
                log.detail( "Client %3d: %s --> %r ", n, dsc, val )
                if not val:
                    log.warning( "Client %d harvested %d/%d results", n, len( results ), times * len( tags ))
                    failures       += 1
                results.append( (dsc,val) )
        if len( results ) != times * len( tags ):
            log.warning( "Client %d harvested %d/%d results", n, len( results ), times * len( tags ))
            failures	       += 1

        return 1 if failures else 0

    failed			= network.bench( server_func=enip.main,
                                                 server_kwds=svrkwds,
                                                 client_func=clitest,
                                                 client_count=1,
                                                 client_max=10 )

