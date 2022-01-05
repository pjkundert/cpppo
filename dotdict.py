
#import logging
import copy
import threading
import multiprocessing
import multiprocessing.managers
import sys

class dotdict_base( object ):
    """A dict supporting keys containing dots, to access a heirarchy of dotdicts and lists of dotdicts.
    Furthermore, if the keys form valid attribute names, values are also accessible via dotted
    attribute name access:
    
        >>> d = dotdict()
        >>> d["a.b"] = 1
        >>> d.a.b
        >>> 1

    Every '..' in the key back-tracks by one key element (these ignored elements are not checked for
    validity), much like a file-system:

        >>> d['a.x..b']    # same as d['a.b']
        >>> 1
        >>> d['a.x.y...b'] # and works for multiple levels, one dot per level
        >>> 1
        >>> d['a.....a.b'] # and back-tracking past root is OK
        >>> 1

    Any string valid as an attribute name should be valid as a key (leading '.' ignored):

        >>> d.a.b
        >>> 1
        >>> d['.a.b']
        >>> 1

    While the key iterator only returns actual value keys:

        >>> [k for k in d]
        >>> ['a.b']

    the test for 'in' returns partially specified keys (so setdefault works):

        >>> 'a' in d
        >>> True

    but deletion won't allow deleting non-empty levels of the dotdict (but pop will):

        >>> del d['a']
        Traceback ...
        KeyError: 'cannot del "a" (partial key)'

    Lists of dotdicts can be indexed directly within a key (including simple math and references to
    other "peer" dotdict values at or below the same level), and are represented as indexes when
    keys are iterated:

        >>> d.a = [dotdict()]
        >>> d.a[0].a = 0
        >>> d.a[0].b = 1
        >>> d.keys()
        >>> for k in d: print k
        ...
        a[0].a
        a[0].b
        >>> d['a[0].b']
        1
        >>> d.a[0].b
        1
        >>> d['a[a[0].b-1].b']
        1
        >>>


    NOTE: There is, of course, a restriction on the variety of items/attributes that can be added to
    a dotdict; No item matching one of the standard dict interface methods may be added!  The
    following keys are off-limits, and will result in a KeyError exception.  This shouldn't be a
    significant impediment, as the typically use-case for dotdict/apidict is to transport sets of
    configuration or structural values around, and these usually have known or deterministic names.

    """
    __slots__			= ()
    __invalid_keys__		= (
        'clear', 'copy', 'get', 'set', 'items', 
        'iteritems', 'iterkeys', 'itervalues',
        'listitems', 'listkeys', 'listvalues',
        'keys', 'values',
        'pop', 'popitem', 'setdefault', 'update',
    )

    #def __repr__( self ):
    #    """To be consistent, we should identify ourself as a dotdict({...}), but this is cluttered."""
    #    return self.__class__.__name__ + '(' + super( dotdict, self ).__repr__() + ')'

    def __init__( self, *args, **kwds ):
        """Load from args, update from kwds"""
        super( dotdict_base, self ).__init__()
        self.update( *args, **kwds )

    def update( self, *args, **kwds ):
        """Give each dict or k,v iterable, and all keywords a chance to be converted into a dotdict() layer.

        """
        # There is a defect in python 3.7 that erroneously passes back a single dict object passed
        # to dict.__init__ as the result...   
        assert 0 <= len( args ) <= 1, "A single dict or iterable of key/value pairs is allowed"
        if args and isinstance( args[0], dict ) and type(args[0]) is not dict:
            args = (dict.items( args[0] ),)
        for key, val in dict( *args, **kwds ).items():
            self.__setitem__( key, val )

    def __dir__( self ):
        """We try to present a sensible .attribute interface.  Therefore, it doesn't make sense for
        dir(<dotdict>) to return all the normal attributes available in a dict() object's .__dict__;
        we'll return the top-level keys in the underlying dict instead (and the magic methods).
        This is more or less consistent with an object (except it won't return any of the expected
        "magic" __methods__).  So, creating attribute .a with:

            >>> d = dotdict()
            >>> d.a = 1
            >>> dir( d )
            [ ..., "a", ... ]

        """
        return sorted(
            [
                a for a in dir( super( dotdict_base, self ))
                if a.startswith( '__' )
            ] + list( super( dotdict_base, self ).keys())
        )

    #_resolve_cache		= {}
    def _resolve( self, key ):
        """Return next segment in key as (mine, rest), solving for any '..'  back-tracking.  If key
        begins/ends with ., or too many .. are used, the key will end up prefixed by ., 'mine' will
        end up '', raising KeyError.  Avoid calling if there are no '.' in key.

        """
        # tpl			= dotdict._resolve_cache.get( key, None )
        # if tpl:
        #     return tpl

        # Process '..' back-tracking
        #     'a.b..c'     ==> 'a.c'  ; split == ['a.b',   'c'  ]
        #     'a.b.c...d'  ==> 'a.d'  ; split == ['a.b.c', '.d' ]
        mine, rest 		= key, None
        while '..' in mine:
            front, back		= mine.split( '..', 1 )
            trunc		= front[:max(0,front.rfind('.'))]
            mine		= trunc + ( '.' if ( trunc and back ) else '' ) + back
            #logging.info( '_resolve reduced "%s..%s" to "%s"' % ( front, back, mine ))
        # Find leading non-. term
        while '.' in mine:
            mine, rest		= mine.split( '.', 1 )
            if mine:
                # Found 'mine' . 'rest'; if unbalanced brackets, eg 'a[b.c].d.e' ==> 'a[b' 'c].d.e',
                # then keep moving split 'til balanced.
                if '[' in mine:
                    terms	= { '[':1, ']':-1 }
                    while sum( terms.get( c, 0 ) for c in mine ):
                        #logging.info( '_resolve unbalanced %r.%r"' % ( mine, rest ))
                        if not rest:
                            raise KeyError( "unbalance brackets in %s" % key )
                        ext,rest= rest.split( '.', 1 )
                        mine   += '.' + ext
                break
            mine		= rest
        if not mine:
            raise KeyError('cannot resolve "%s" in "%s" from key "%s"' % ( rest, mine, key ))

        #dotdict._resolve_cache[key] = tpl = (mine, rest)
        tpl = (mine, rest)
        return tpl

    def __setitem__( self, key, value ):
        """Assign a value to an item. """
        mine,rest		= self._resolve( key ) if '.' in key else (key,None)
        if rest:
            if '[' in mine:
                # If indexing used in path down to target, must be pre-existing values
                target          = eval( mine, {'__builtins__':{}}, self )
            else:
                target          = super( dotdict_base, self ).setdefault( mine, dotdict() )
            if not isinstance( target, dotdict_base ):
                raise KeyError( 'cannot set "%s" in "%s" (%r)' % ( rest, mine, target ))
            target[rest]        = value
        else:
            if isinstance( value, dict ) and not isinstance( value, dotdict_base ):
                # We considered converting anything with the "mapping protocol" (.keys() and
                # .__getitem__) to a dotdict, here.
                # https://stackoverflow.com/questions/35282222/in-python-how-do-i-cast-a-class-object-to-a-dict
                # However, we want to be able to add complex proxies for dotdicts here (such as
                # multiprocessing proxies for apidict).  Therefore, only identify plain dicts that
                # are not already some derivation of dotdict_base, adn convert them to our class.
                value           = self.__class__( value )
            if '[' in mine and mine[-1] == ']':
                # If indexing used within the final item/attr key, it must encompass the entire
                # final portion of the key; break out the attr[indx], and safely eval it to get the
                # actual index.  Finally, get the object and let it do its own __setitem__.
                mine, indx	= mine.split( '[', 1 )
                indx		= eval( indx[:-1], {'__builtins__':{}}, self )
                super( dotdict_base, self ).__getitem__( mine )[indx] = value
            else:
                if mine in self.__invalid_keys__ or mine.startswith( '__' ):
                    raise KeyError( "A dotdict cannot support insertion of item/attribute with name {!r}".format( mine ))
                super( dotdict_base, self ).__setitem__( mine, value )

    def __setattr__( self, key, value ):
        """Create attributes as easily as creating keys, so AttributeError should be unexpected.  Specify a
        method (instead of __setattr__ = __setitem__) to support overriding."""
        self.__setitem__( key, value )

    def __getitem__( self, key ):
        """Locate an item by key: either via indexing, or attribute access:

           <dotdict>['name']
           <dotdict>.name

        If we find something like 'name[1]' or 'name[a.b[c+3]]', etc: resolve it allowing no access
        to globals or builtin functions, and only our own dotdict as locals: cannot index using
        values from higher levels of the dotdict, eg. 'name[..above]'

        Note also that the hasattr builtin used getattr to identify the existence of attributes; it
        must return AttributeError if the attribute doesn't exist."""
        mine,rest		= self._resolve( key ) if '.' in key else (key,None)
        if '[' in mine:
            target              = eval( mine, {'__builtins__':{}}, self )
        else:
            target              = super( dotdict_base, self ).__getitem__( mine )
        if rest is None:
            return target
        # We have the rest of the levels to go; must have addressed another dotdict level (or
        # something else that is subscriptable).
        getter			= getattr( target, '__getitem__', None )
        if getter is None:
            raise KeyError( 'cannot get "%s" in "%s" (%r); not subscriptable' % ( rest, mine, target ))
        return getter( rest )

    def __getattr__( self, key ):
        try:
            return self.__getitem__( key )
        except KeyError as exc: 
            raise AttributeError( str( exc ))

    def __contains__( self, key ):
        """In a normal dict b, "'a' in b" is True iff the indexed element exists
        and is a value.  We would implement the same concept here (key is not
        another layer of dotdict), like this:

            try:
                return not isinstance( self.__getitem__( key ), dotdict_base )
            except KeyError:
                return False
                
        However, for things like setdefault and equivalent code to work
        sensibly, we need to return True even when a key exists, and its just
        another layer of dotdict, to avoid wiping out layers of our dotdict with
        code like:
        
            d = dotdict()
            d.a.b.c = 1
            if 'a.b' not in d:
                d.a.b = "something" # just lost whole d.a.b dotdict()!

        So, return True if anything exists in the dotdict at the given key."""
        try:
            self.__getitem__( key )
            return True
        except KeyError:
            return False

    def __delitem__( self, key ):
        """We are more strict for 'del d[key]' than for 'key in d'; we will only
        delete keys that are not further layers of dotdict (ie. a partial key).
        We could auto-del empty layers by adding, but this would probably be
        unexpected (they don't show up in key iteration, anyway):

            # Empty layers deleted 
            if 0 == len( target ):
                super( dotdict_base, self ).__delitem__( mine )
        """
        mine,rest		= self._resolve( key ) if '.' in key else (key,None)
        #logging.debug("del %s, from: %s (in %r)", rest, mine, self )
        # will raise KeyError if no such key...
        target			= self[mine]
        if rest is None:
            # will raise KeyError if partial key (dotdict layer) not empty
            if isinstance( target, dotdict_base ) and len( target ):
                raise KeyError( 'cannot del "%s" (partial key)' % ( mine ))
            return super( dotdict_base, self ).__delitem__( mine )
        del target[rest]

    def pop( self, *args ):
        """Pop doesn't take keyword args, but default is optional.  So, we can only
        override this by capturing args."""
        key			= args[0]
        mine,rest		= self._resolve( key ) if '.' in key else (key,None)
        if rest is None:
            return super( dotdict_base, self ).pop( mine, *args[1:] )
        target                  = super( dotdict_base, self ).__getitem__( mine )
        if not isinstance( target, dotdict_base ):
            raise KeyError( 'cannot pop "%s" in "%s" (%r)' % ( rest, mine, target ))
        return target.pop( rest, *args[1:] )

    def setdefault( self, key, default ):
        if key not in self:
            self[key]           = default
        return self[key]

    def get( self, key, default=None ):
        """The default dict.get is not implemented in terms of __getitem__.  Provide it, and also a set
        implemented in terms of __setitem__ (eg. for use by derived classes or proxies that cannot
        use __setattr__.

        """
        try:
            return self.__getitem__( key )
        except KeyError:
            return default

    set			= __setitem__

    def iteritems( self, depth=None ):
        """Issue keys for layers of dotdict() in a.b.c... form.  For dotdicts containing a list of
        dotdict, issue keys in a.b[0].c form, since we can handle simple indexes in paths for
        indexing (we'll arbitrarily limit it to just one layer deep).

        An optional depth limits the key length; by default, we'll issue full-depth keys; To
        approximate the normal dict.items() (which returns only the current dict's key/value pairs),
        call with depth=1.

        This flows through to all {iter,list}{items,values,keys} API calls.
        """
        items			= super( dotdict_base, self ).iteritems if sys.version_info[0] < 3 else super( dotdict_base, self ).items
        for key,val in items():
            if isinstance( val, dotdict_base ) and val and ( depth is None or depth > 0 ):
                # a non-empty sub-dotdict layer, and we have depth remaining
                for subkey,subval in val.iteritems( None if depth is None else depth - 1 ):
                    yield key+'.'+subkey, subval
            elif isinstance( val, list ) and val and all( isinstance( subelm, dotdict_base ) for subelm in val ):
                # Non-empty list of dicts
                subfmt		= "[{subidx:%d}]." % len( str( len( val ) - 1 ))
                for subidx,subelm in enumerate( val ):
                    for subkey,subval in subelm.iteritems():
                        yield key+subfmt.format( subidx=subidx )+subkey, subval
            else: # non-list elements, empty dotdict layers, empty lists
                yield key, val


    def listitems( self, depth=None ):
        return list( self.iteritems( depth=depth ))

    def itervalues( self, depth=None ):
        for key,val in self.iteritems( depth=depth ):
            yield val

    def listvalues( self, depth=None ):
        return list( self.itervalues( depth=depth ))

    def iterkeys( self, depth=None ):
        for key,val in self.iteritems( depth=depth ):
            yield key

    def listkeys( self, depth=None ):
        return list( self.iterkeys( depth=depth ))

    __iter__			= iterkeys
    keys 			= iterkeys     if sys.version_info[0] > 2 else listkeys
    values			= itervalues   if sys.version_info[0] > 2 else listvalues
    items			= iteritems    if sys.version_info[0] > 2 else listitems

    def __deepcopy__( self, memo ):
        """Must copy each layer, to avoid copying keys that reference non-existent members."""
        return type( self )( (k,copy.deepcopy( v, memo ))
                             for k,v in super( dotdict_base, self ).items() )

    def __copy__( self ):
        return type( self )( (k,copy.copy( v ))
                             for k,v in super( dotdict_base, self ).items() )



class dotdict( dotdict_base, dict ):
    pass


class apidict_base( dotdict ):
    """A dotdict that ensures that any new values assigned to its attributes are very likely received
    by some other thread (via .__getattr__ or .get) before the corresponding __setattr__, setdefault
    or set returns; setting/getting values by indexing (ie. like a normal dict) is *not* affected
    (except for locking), allowing the user to selectively force timeout 'til read on some
    assignments but not others, and to indicate reception of the value on some reads and not others.

    A specified timeout (required as first argument) is enforced after __setattr__, setdefault or
    set, which is only shortened when another thread executes a __getattr__/get.

    Note that getting *any* attr on the apidict releases all threads blocked setting *any* attr!
    So, use index access to read the bulk of values, and finally a single __getattr__/get to access
    the last value, and indicate completion of access.

    """
    __slots__			= ('_lck', '_cnd', '_tmo')

    def __init__( self, timeout, *args, **kwds ):
        object.__setattr__( self, '_lck', self._sync_mod.RLock() )
        object.__setattr__( self, '_cnd', self._sync_mod.Condition( self._lck ))
        if isinstance( timeout, apidict_base ):
            # Special case for copying another apidict; pass k,v pairs as 1st args
            assert not args, "Unable to support copying apidict w/ iterable of k,v"
            object.__setattr__( self, '_tmo', timeout._tmo )
            args		= (timeout.listitems( depth=1 ), )
        else:
            assert isinstance( timeout, (float,int) ), \
                "First argument to apidict must be a numeric timeout (or another apidict)"
            object.__setattr__( self, '_tmo', timeout )
        super( apidict_base, self ).__init__( *args, **kwds )

    def __setitem__( self, key, value ):
        with self._cnd:
            super( apidict_base, self ).__setitem__( key, value )
        
    def __setattr__( self, key, value ):
        with self._cnd:
            super( apidict_base, self ).__setattr__( key, value )
            self._cnd.wait( self._tmo )

    def set( self, key, value ):
        with self._cnd:
            super( apidict_base, self ).set( key, value )
            self._cnd.wait( self._tmo )

    def setdefault( self, key, default ):
        with self._cnd:
            was			= super( apidict_base, self ).setdefault( key, default )
            self._cnd.wait( self._tmo )
            return was

    def __getitem__( self, key ):
        with self._cnd:
            return super( apidict_base, self ).__getitem__( key )

    def __getattr__( self, key ):
        with self._cnd:
            try:
                return super( apidict_base, self ).__getattr__( key )
            finally:
                self._cnd.notify_all()

    def get( self, key, default=None ):
        with self._cnd:
            try:
                return super( apidict_base, self ).get( key, default=default )
            finally:
                self._cnd.notify_all()


class apidict_threading( apidict_base):
    _sync_mod			= threading


class apidict( apidict_base ):
    """Works in both threading and multiprocessing environments."""
    _sync_mod			= multiprocessing


#
# To use apidict via multiprocessing.Process, we can proxy the API -- but these proxies cannot
# successfully proxy __getattr__/__setattr__.  So, users must employ set/get instead;
# .set/.setdefault will block 'til a counterparty executes .get().
#
def make_apidict_proxy( apidict_class ):
    """Product a tuple usable to call SyncManager.register, for the given apidict derived class.
    Supplies its __name__ as "<name>_proxy" for the proxy, and registers the bare "<name>" with the
    multiprocessing Manager.

    """
    apidict_proxy		= multiprocessing.managers.MakeProxyType(
        apidict_class.__name__ + '_proxy', (
            '__contains__', '__delitem__', '__getitem__', '__iter__', '__len__',
            '__setitem__', 'clear', 'copy', 'get', 'set'
            # These will not work in python3, as they return generators; use list( <apidict> )
            # instead, as the __iter__ method is supported and returns the keys.
            'items', 'keys',
            'pop', 'popitem', 'setdefault', 'update', 'values'
            '__dir__', 'set', # '__setattr__', '__getattr__',
            # 'iteritems', 'iterkeys', 'itervalues',  # These cannot be proxied, as they return generations
            'listitems', 'listkeys', 'listvalues',
        )
    )
    apidict_proxy._method_to_typeid_ = {
        '__iter__': 'Iterator',
    }
    return apidict_class.__name__, apidict_class, apidict_proxy

multiprocessing.managers.SyncManager.register( *make_apidict_proxy( apidict ))
