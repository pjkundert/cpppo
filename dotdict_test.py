from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import json
import logging
import multiprocessing
import os
import random
import sys
import threading
import time

from . import misc
from .dotdict import dotdict, apidict, make_apidict_proxy


def test_dotdict_smoke():
    # Like dict, construct from mapping, iterable and/or keywords
    assert "a" in dotdict({"a":1})
    assert dotdict({"a":1})["a"] == 1

    assert "b" in dotdict({"a":1}, b=2)
    assert dotdict({"a":1}, b=2)["b"] == 2

    assert "c" in dotdict([("c",3)], d=4)
    assert dotdict([("c",3)], d=4)["c"] == 3

    assert "e" in dotdict(e=5)
    assert dotdict(e=5)["e"] == 5

    # Create hierarchies by assignment
    d = dotdict()
    d["a.b"] = 1
    assert d["a.b"] == 1
    assert d.a.b == 1		# attribute access =~= indexing
    d.a.b = 2
    assert d["a.b"] == 2
    assert d.a.b == 2

    # but only one layer at a time by attribute access
    try:
        d.x.y = 99
        assert False, "Shouldn't be able to create y in non-existent x!"
    except AttributeError as e:
        assert "'x'" in str( e )

    # dicts already containing dotted keys are converted when assigned
    d2 = {"c.d": 2}
    d.a.b = d2
    assert d.a.b.c.d == 2

    assert "b.c.d" in d.a
    assert "b.c.x" not in d.a
    assert "e.f" not in d.a
    assert "a.b" in d     # Not a value, but is another layer of dotdict
    assert "a.b.x...b.c.d" in d
    assert "a.b.x....a.b.c.d" in d
    assert "a.b.x" not in d
    assert "a.b.c" in d

    assert isinstance( d.a.b.setdefault( 'c', "boo" ), dotdict )

    # Now, test paths containing back-tracking "a.b..c" ==> "a.c".  Of course,
    # this only works with indexing, not attribute access.  Leading '.' are OK
    # in indexes, consistent with 
    d.a.x = 3
    assert d["a.x"] == 3
    assert d[".a.x"] == 3
    assert d["a.b..x"] == 3
    assert d["a.b.c.d....x"] == 3
    # and back-tracking past root is OK (just like in filesystems)
    d["a...a.x"]
    d["a.b.c...x"]
    assert "a.....a.x" in d
    try:
        d["a.b.c...y"]
        assert False, "Should have failed trying to find y in root"
    except KeyError as e:
        assert "'y'" in str( e ) 

    # back-tracking doesn't confirm the validity of the ignored key elements:
    assert d["a.b.c.d.e.f....d"] == 2

    # key iteration
    assert list( sorted( k for k in d )) == ['a.b.c.d', 'a.x']

    # Make sure keys/items returns a list/iterator appropriate to Python version
    import types
    assert isinstance( d.keys(), list if sys.version_info[0] < 3 else types.GeneratorType )
    assert isinstance( d.items(), list if sys.version_info[0] < 3 else types.GeneratorType )


    # Test deletion, including refusing partial keys (unless empty)
    try:
        del d["a.b.c"]
    except KeyError as e:
        assert "(partial key)" in str( e ) 
    del d["a.b.c.d"]
    # key iteration (does not ignore empty key layers)
    assert list( sorted( k for k in d )) == ['a.b.c', 'a.x']
    del d["a.b.c"]
    assert list( sorted( k for k in d )) == ['a.b', 'a.x']
    # We can dig down using attribute access
    assert d.a.x == 3
    try:
        del d.a.x
    except AttributeError as e:
        assert "x" in str( e )
    del d.a["x"]
    assert list( sorted( k for k in d )) == ['a.b']
    assert "a" in d
    assert "b" in d.a
    assert "c" not in d.a.b
    del d["a.b"]
    del d["a"]
    assert list( sorted( k for k in d )) == []

    # pop has no such restrictions; it will happily pop and return a value or non-empty dotdict
    d["a.b.c.d"] = 2
    d["a.x"] = 3
    assert d.a.b.c.d == 2
    assert d.pop("a.b.c") == {'d':2}
    assert "a.b" in d
    assert "a.b.c" not in d
    assert "x" in d.a
    assert d.pop("a.b.c...x") == 3
    assert "x" not in d.a


def test_dotdict_indexes():
    """Indexing presently only works for __getitem__, get; not implemented/tested for __setitem__,
    setdefault, del, pop, etc."""
    d = dotdict()

    d['a.b'] = 1
    d['c'] = 2
    d['l'] = [1,2,3,dotdict({'d':3})]

    assert d._resolve( 'a' ) == ( 'a', None )
    assert d._resolve( 'l[a.b+c].d' ) == ( 'l[a.b+c]', 'd' )

    assert d['l[a.b+c].d'] == 3

    try:
        assert d['l[a.b+c-1].d'] == 3
        assert False, "Indexing int, then trying to resolve another level should fail"
    except KeyError as exc:
        assert "not subscriptable" in str(exc)
        pass

    assert d.get( 'l[a.b+c-1].d' ) == None
    assert d.get( 'l[a.b+c].d' ) == 3

    # Also allow indexes in __setattr__/__setitem__, while finding path down to
    # dotdict item to change:
    d['l[3].d'] = 4
    assert d.get( 'l[a.b+c].d' ) == 4
    d['l[a.b+c].d'] = 5
    assert d.get( 'l[a.b+c].d' ) == 5

    # Also allow (valid) indexes (even using local dotdict names) in the final level
    assert d['l[c-1]'] == 2
    d['l[c-1]'] = 99
    assert d['l[c-1]'] == 99

    try:
        d['l[c+3]'] = 3
        assert False, "Indexing with a bad index should fail"
    except IndexError as exc:
        assert "index out of range" in str(exc)
        pass
    

def test_dotdict_hasattr():
    """Indexing failures returns KeyError, attribute access failures return AttributeError for hasattr
    etc. work.  Also, the concept of attributes is roughly equivalent to our top-level dict keys."""
    d = dotdict()

    d['.a.b'] = 1
    d['.c'] = 2

    assert hasattr( d, 'a' )
    assert hasattr( d, 'a.b' )
    assert not hasattr( d, 'b' )
    assert hasattr( d, 'c' )

    attrs = [ a for a in dir( d ) if not a.startswith('__') ]
    assert 'c' in attrs
    assert 'a' in attrs
    assert 'b' not in attrs
    assert len( attrs ) == 2
    #print( dir( d ))


repeat = 1000
@misc.assert_tps( scale=repeat )
def test_dotdict_performance():
    count = repeat
    while count:
        count -= 1
        test_dotdict_smoke()
        test_dotdict_indexes()


def apidict_latency(
    concurrency_fun,
    apidict_factory		= lambda *args, **kwds: apidict( *args, **kwds ),
    use_attr			= True
):
    """Ensure that latency doesn't apply to initial import of values by constructor, or to setting items
    by indexing; only setting by attribute assignment.  This must occur whether the dotdict/apidict
    is shared between threading.Threads, *or* between multiprocessing.Processes.

    Unfortunately, since multiprocessing.Process proxies don't allow __getattr__/__setattr__ to be
    proxied, we must use set/get

    """

    latency = 0.5
    significance = .2 # w/in 20%, for leeway on slow testing hosts
    beg = misc.timer()
    ad = apidict( latency, something='a', another='b' )
    dif = misc.timer() - beg
    assert dif < latency*significance # should be nowhere near latency (close to zero)
    assert ( ad.something if use_attr else ad.get( 'something' )) == 'a'

    beg = misc.timer()
    if use_attr:
        ad.boo = 1
    else:
        ad.set( 'boo', 1 )
    dif = misc.timer() - beg
    assert dif >= latency
    #assert misc.near( dif, latency, significance=significance ) # rare failures on some Pythons

    beg = misc.timer()
    ad['boo'] = 2
    dif = misc.timer() - beg
    assert dif < latency * significance # but setting items by indexing does not delay!

    # Now, start a thread with a shorter delay; it should invoke __get{attr,item}__, shortening the
    # wait.  Under python 3.3, threading.Condition's wait is implemented using non-polling
    # intrinsic; under prior versions, they poll (max .05s; see threading.py, _Condition.wait) -- so
    # the resolution of the timeout test is reduced to be greater than that margin of error.  The
    # 'significance' of the error is expressed as a multiplication factor of the tested values;
    # eg. .1 --> 10% error allowed vs. the greatest absolute value.  For version of python < 3.3, 
    # allow for a factor at least 0.05 vs. the shorter latency, increased by 10%.  
    
    shorter = latency/2.0
    if (sys.version_info[0], sys.version_info[1]) < (3,3):
        significance = max( significance, 0.05 / shorter * 1.1 )

    def release( base, delay, dd, attr=None, item=None ):
        now = misc.timer()
        logging.debug( "started after %7.3fs", now - base )
        when = base + delay
        if when > now:
            time.sleep( when - now )
        if attr:
            if use_attr:		# Will release apidict
                val = getattr( ad, attr )
            else:
                val = ad.get( attr )
        else:
            val = ad[item]		# Won't release apidict
        logging.debug( "got: %s", val )

    # Make sure a single concurrent counterparty releases the condition by performing an
    # getattr(<apidict>,'<attr>') on any attr.
    for kwargs in [ {'attr': 'boo'}, {'item': 'boo'}, {'attr': 'noo'}, {'item': 'noo'} ]:
        # Start the release function, waiting 'til beg+shorter to get/__getattr__ or __getitem__
        beg = misc.timer()
        t = concurrency_fun( target=release, args=(beg, shorter, ad), kwargs=kwargs )
        t.start()
        logging.debug( "set; significance: {significance}".format( significance=significance ))
        if use_attr:   # blocks 'til Thread releases apidict
            ad.noo = 3
        else:
            ad.set( 'noo', 3 )
        dif = misc.timer() - beg
        err = abs( shorter - dif )
        logging.debug( "end; dif: %s, err: %s ==> %s", dif, err, err/shorter )
        # There are unexplained issues with some version of Python (ie. 3.4), with occasional
        # larger than expected delays...  So, just test </>= against full latency 
        assert dif < latency if 'attr' in kwargs else dif >= latency, \
            "Expected {} {} {}, due to use of __get{}__ in counterparty".format(
                dif, '< ' if 'attr' in kwargs else '>=', latency,
                'attr' if 'attr' in kwargs else 'item'
            )
        #assert misc.near( dif, shorter if 'attr' in kwargs else latency, significance=significance )
        assert ad.noo == 3
        t.join()

    # Ensure multiple concurrent counterparties are each unblocked by an attribute access in one (or
    # more) of them.  This means that all writers of attribute value should be received by at least
    # one reader.

    def grind( thing, number_range, getter_count ):

        def setter( shared, i, beg, end ):
            """Sets inputs["#"].value to a range of values, one at a time."""
            for value in range( beg, end ):
                # An apidict should block 'til *someone* retrieves this value.  A dotdict/dict not
                # so much.
                time.sleep(0.001)
                if use_attr:
                    shared.inputs[i].value = value
                else:
                    shared.inputs[i].set( 'value', value )
            shared.inputs[i].set( 'value', None )

        def getter( shared, i ):

            def finder():
                """Iterate over the shared.inputs[...].value, until all of them are exhausted (are None)"""
                found			= True
                while found:
                    found		= False
                    for s_i in dict.keys( shared.inputs ):
                        time.sleep(random.random() * 0.1) # 0.0-0.1 seconds
                        # should unblock all counterparties to proceed
                        v		= shared.inputs[s_i].value if use_attr else shared.inputs[s_i].get( 'value' )
                        if v is not None:
                            found	= True
                            yield v

            # Take not of each unique value found in any of the inputs["#"].value
            results			= set()
            for v in finder():
                logging.detail( "Got value {v} in pid,tid: {caller}".format( v=v, caller=caller() ))
                results.add( v )
            logging.normal( "Found {rlen} values in pid,tid: {caller}: {results!r}".format(
                rlen=len(results), caller=caller(), results=results))
            shared.results[i] = results

        # thing.results is an apidict that will contain lists of inputs[...].value seen by each enumerated getter

        thrs			= []
        for s_num in dict.keys( thing.inputs ): # want "0", "1", ... not "0.value", ...
            beg			= ( int( s_num ) + 0 ) * number_range
            end			= ( int( s_num ) + 1 ) * number_range
            s			= concurrency_fun(
                target	= setter,
                args	= (thing, str( s_num ), beg, end,)
            )
            s.start()
            logging.info( "setter {} starts {:3d} - {:3d}".format( s.name, beg, end ))
            thrs.append( s )

        for g_num in range( getter_count ):
            g			= concurrency_fun(
                target	= getter,
                args	= (thing, str( g_num ))
            )
            g.start()
            logging.info( "getter {} starts".format( g.name ))
            thrs.append( g )

        for t in thrs:
            t.join()
            logging.info( "thread {} done".format( t.name ))

        return thing

    inputs_range		= 7
    number_range		= 10
    getter_count		= 5

    ad_result			= grind(
        dotdict(
            inputs	= {
                str(i): apidict_factory( timeout=1.0, value=-1 )
                for i in range( inputs_range )
            },
            results	= apidict_factory( timeout=1.0 ),
        ),
        number_range	= number_range,
        getter_count	= getter_count,
    )

    import json
    # logging.normal( "w/ dotdict: {}".format( json.dumps( dd_result, indent=4, default=str )))
    logging.normal( "w/ apidict: {}".format( json.dumps( ad_result, indent=4, default=str )))
    seen			= set()
    for i in ad_result.results:
        seen			= seen.union( ad_result.results[i] )
    logging.normal( "seen: {}".format( json.dumps( seen, indent=4, default=str )))
    assert seen == set( range( inputs_range * number_range ))
    

def test_apidict_threading():
    apidict_latency( threading.Thread, use_attr=True )
    apidict_latency( threading.Thread, use_attr=False )


class MySyncManager(multiprocessing.managers.SyncManager):
    if sys.version_info[0] < 3:
        def shutdown( self ):
            pass


def caller():
    return os.getpid(),threading.current_thread().ident


class apidict_recording( apidict ):
    """An apidict that records some stats"""
    def set( self, key, value ):
        logging.normal( "set {key:16} in pid,tid: {caller!r} = {value}...".format(
            key		= key,
            caller	= caller(),
            value	= value,
        ))
        beg			= misc.timer()
        exc			= None
        try:
            super( apidict_recording, self ).set( key, value )
        except Exception as exc:
            raise
        finally:
            end			= misc.timer()
            dur			= end - beg
            pct			= int( 100 * dur / self._tmo )
        logging.normal( "set {key:16} in {dur:8.3f}s ({pct:>3d}% of timeout) w/ exc: {exc!r}".format(
            key	= key,
            dur	= dur,
            pct	= pct,
            exc	= exc,
        ))

    def get( self, key, default=None ):
        value			= None
        exc			= None
        try:
            value		= super( apidict_recording, self ).get( key, default=default )
            return value
        except Exception as exc:
            raise
        finally:
            logging.normal( "got {key:16} in pid,tid: {caller!r} = {value} w/ exc: {exc!r}".format(
                key	= key,
                caller	= caller(),
                value	= value,
                exc	= exc,
            ))


MySyncManager.register( *make_apidict_proxy( apidict_recording ))


def test_apidict_multiprocessing():

    with MySyncManager() as m:
        if sys.version_info[0] < 3:
            m.start()
        apidict_latency(
            multiprocessing.Process,
            apidict_factory	= lambda *args, **kwds: m.apidict_recording( *args, **kwds ),
            use_attr		= False,
        )


def test_dotdict_multiprocessing_proxies():
    """Ensure that we understand the 3 ways Python objects can be passed to and accessed by remote
    multiprocessing.Process processes:

    1) Plain classes, with underlying code copied to remote Process.  No synchronization.
    2) The remote instance(s) contain multiprocessing.RLock, .Condition, etc., which cooperate via a central Manager() instance.
    3) The central Manager houses the one true instance, and remote instance API calls are proxied back to the central instance.

    Since a proxy cannot call a function that returns a proxy (ie. itself), and since dot/apidict
    works by returning the *next* layer of dotdict/apidict on an __getattr__ call (eg. a.b.c), we
    cannot use option 3) -- the underlying dict calls must be proxied, not the class itself.

    So, each dot/apidict must be implemented in terms of either a plain dict(), or a
    multiprocessing Manager.dict(), provisioned by a specific Manager instance.  Therefore,
    it must not be a sub-class.

    """

    class where_am_i( object ):
        def __init__( self, calls ):
            self._calls		= calls
            logging.normal( "Created where_am_i id({}): {}".format(
                id( self ), repr( self.calls )))

        def function( self, rem_pid, rem_tid ):
            loc_pid,loc_tid	= caller()
            logging.normal( "Called  where_am_i id({}) .function here {}, from {}".format(
                id(self), (loc_pid, loc_tid), (rem_pid, rem_tid) ))
            self._calls.append( ((rem_pid, rem_tid), (loc_pid, loc_tid)) )

        def calls( self ):
            return list( self._calls )


    def call_function( w ):
        try:
            by			= caller()
            logging.normal( "{!r}.function{!r} call...".format( w, by ))
            w.function( *by )
        except Exception as exc:
            logging.warning( "{!r}.function() failed: {}".format( w, exc ))


    # Simple object, threading.Thread.  Everything in local process' PID and same Thread.ident
    wai				= where_am_i( [] )
    assert isinstance( wai, where_am_i )
    assert wai.calls() == []
            
    t				= threading.Thread(
        target		= call_function,
        args		= (wai,),
    )
    t.start()
    t.join()

    logging.normal( "Threading where_am_i.calls: {}".format(
        json.dumps( wai.calls(), indent=4 )))
    assert len( wai.calls() ) == 1
    assert all( rp == lp == os.getpid() and rt == lt for (rp,rt),(lp,lt) in wai.calls() )

    # Use multiprocessing.Manager instance to host just the data contents of an object; the object
    # itself is still local in each of the Main Thread and the remote Process.
    
    # Simple object, multiprocess.Process.  Everything in remote process' PID and same Thread.ident
    with multiprocessing.Manager() as m:
        wai_mp_list		= where_am_i( m.list() )

        p			= multiprocessing.Process(
            target	= call_function,
            args	= (wai_mp_list,),
        )
        p.start()
        p.join()

        logging.normal( "Process PID == {} where_am_i.calls: {}".format(
            p.pid, json.dumps( list( wai_mp_list.calls() ), indent=4 )))
        assert len( wai_mp_list.calls() ) == 1
        assert all( rp == lp == p.pid and rt == lt for (rp,rt),(lp,lt) in wai_mp_list.calls() )

    # Use multiprocessing.Manager instance to host the entire object.  Calls from both the Main
    # Thread the remote Process come back to the Manager Process.

    # Custom proxied object, multiprocess.Process.  Local method called by remote caller.
    class where_am_i_proxy( multiprocessing.managers.BaseProxy ):
        _exposed_		= ("function", "calls")
        def function( self, *args, **kwds ):
            return self._callmethod( "function", args, kwds )
        def calls( self, *args, **kwds ):
            return self._callmethod( "calls", args, kwds )


    MySyncManager.register("where_am_i_proxy", where_am_i, where_am_i_proxy )

    with MySyncManager() as m:
        if sys.version_info[0] < 3:
            m.start()
        wai_proxy		= m.where_am_i_proxy( [] )
        
        p2			= multiprocessing.Process(
            target	= call_function,
            args	= (wai_proxy,),
        )
        p2.start()
        p2.join()

        logging.normal( "Process PID == {}, SyncManager PID == {} w/ proxied where_am_i.calls: {}".format(
            p2.pid, m.address, json.dumps( list( wai_proxy.calls() ), indent=4 )))
        assert len( wai_proxy.calls() ) == 1
        assert all( rp == p2.pid
                    and lp != os.getpid() # Manager is in a different process
                    and rt != lt
                    for (rp,rt),(lp,lt) in wai_proxy.calls() )
    
    # Auto-proxied object, multiprocess.Process.  Local method called by remote caller.
    MySyncManager.register( 'where_am_i', where_am_i )

    with MySyncManager() as m:
        if sys.version_info[0] < 3:
            m.start()
        wai_autoproxied		= m.where_am_i( [] )
        
        p2			= multiprocessing.Process(
            target	= lambda w: w.function( *caller() ),
            args	= (wai_autoproxied,),
        )
        p2.start()
        p2.join()

        logging.normal( "Process PID == {} w/ proxied where_am_i.calls: {}".format(
            p2.pid, json.dumps( list( wai_autoproxied.calls() ), indent=4 )))
        assert len( wai_autoproxied.calls() ) == 1
        assert all(
            rp == p2.pid
            and lp != os.getpid() # Manager is in a different process
            and rt != lt
            for (rp,rt),(lp,lt) in wai_autoproxied.calls() )


    # We want a proxy dict provided to the Main Thread and all sub-Processes, where a sub-Process
    # can receive data and place values, such that the Main Thread can retrieve them.

    # Confirm that apidict timeout and bi-directional communication works between the Main Thread
    # and sub-Processes.

    with MySyncManager() as m:
        if sys.version_info[0] < 3:
            m.start()
        logging.normal( "MySyncManger w/ PID {pid!r}".format( pid=m._process.pid ))
        latency			= 2.0
        ad_proxied		= m.apidict_recording( latency, value=0 )
        def ad_target( ad, beg, wait ):
            ad['world']		= 'Hello'
            ad['pid'],ad['tid']	= caller()
            ad['value']	       += 1
            time.sleep( max( 0, misc.timer() - beg + wait ))
            ad.get( 'target' )

        def dd_target( dd, beg, wait ):
            dd.ad['world']	= 'There'
            dd.ad['pid'],dd.ad['tid'] = caller()
            dd.ad['value']     += 1
            time.sleep( max( 0, misc.timer() - beg + wait ))
            dd.ad.get( 'target' )

        now			= misc.timer()
        p2			= multiprocessing.Process(
            target	= ad_target,
            args	= (ad_proxied, now, latency/2 ),
        )
        p2.start()
        # Should delay by ~1.0s (half of apidict's latency) from when p2 was created
        now			= misc.timer()
        ad_proxied.set( 'target', "set by pid,tid: {caller!r}".format( caller=caller() ))
        dur		= misc.timer() - now
        pct		= int( 100 * dur / latency )
        logging.normal( "set of target took {dur:8.3f}s; about {pct:>3d}% of apidict latency {latency}".format(
            dur		= dur,
            pct		= pct,
            latency	= latency
        ))
        p2.join()
        
        logging.normal( "apidict_proxied = {}".format(
             json.dumps( dict([
                 (k, ad_proxied[k]) for k in ('world', 'pid', 'tid', 'value')
             ]), indent=4, default=dict )))

        assert ad_proxied.get( 'world' ) == 'Hello'
        assert ad_proxied.get( 'pid' ) == p2.pid
        assert ad_proxied.get( 'value' ) == 1
        assert 50 <= pct <= 60  # Allow for slow testing hosts

        # OK, now lets try a dotdict tree with a proxied apidict inside it.  The dotdict should be
        # sent through intact, and the aptdict_proxy should be accessible via __getitem__/__setitem__

        dd			= dotdict( ad=ad_proxied )
        now			= misc.timer()
        p3			= multiprocessing.Process(
            target	= dd_target,
            args	= (dd, now, latency/2 ),
        )
        p3.start()
        # Should delay by ~1.0s (half of apidict's latency) from when p2 was created
        now			= misc.timer()
        ad_proxied.set( 'target', "set by pid,tid: {caller!r}".format( caller=caller() ))
        dur		= misc.timer() - now
        pct		= int( 100 * dur / latency )
        logging.normal( "set of target took {dur:8.3f}s; about {pct:>3d}% of apidict latency {latency}".format(
            dur		= dur,
            pct		= pct,
            latency	= latency
        ))
        p3.join()

        logging.normal( "apidict_proxied = {}".format(
             json.dumps( dict([
                 (k, ad_proxied[k]) for k in ('world', 'pid', 'tid', 'value')
             ]), indent=4, default=dict )))

        assert ad_proxied.get( 'world' ) == 'There'
        assert ad_proxied.get( 'pid' ) == p3.pid
        assert ad_proxied.get( 'value' ) == 2
        assert 50 <= pct <= 60
