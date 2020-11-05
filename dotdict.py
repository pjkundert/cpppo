
#import logging
import copy
import threading
import sys

class dotdict( dict ):
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

    """
    __slots__ = ()

    #def __repr__( self ):
    #    """To be consistent, we should identify ourself as a dotdict({...}), but this is cluttered."""
    #    return self.__class__.__name__ + '(' + super( dotdict, self ).__repr__() + ')'

    def __init__( self, *args, **kwds ):
        """Load from args, update from kwds"""
        dict.__init__( self )
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
        return sorted( [ a for a in dir( super( dotdict, self )) if a.startswith( '__' ) ] + list( dict.keys( self )))

    _resolve_cache		= {}
    def _resolve( self, key ):
        """Return next segment in key as (mine, rest), solving for any '..'  back-tracking.  If key
        begins/ends with ., or too many .. are used, the key will end up prefixed by ., 'mine' will
        end up '', raising KeyError.  Avoid calling if there are no '.' in key.

        """
        tpl			= dotdict._resolve_cache.get( key, None )
        if tpl:
            return tpl

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

        dotdict._resolve_cache[key] = tpl = (mine, rest)
        return tpl

    def __setitem__( self, key, value ):
        """Assign a value to an item. """
        mine,rest		= self._resolve( key ) if '.' in key else (key,None)
        if rest:
            if '[' in mine:
                # If indexing used in path down to target, must be pre-existing values
                target          = eval( mine, {'__builtins__':{}}, self )
            else:
                target          = dict.setdefault( self, mine, dotdict() )
            if not isinstance( target, dotdict ):
                raise KeyError( 'cannot set "%s" in "%s" (%r)' % ( rest, mine, target ))
            target[rest]        = value
        else:
            if isinstance( value, dict ) and not isinstance( value, dotdict ):
                # When inserting other dicts, convert them to dotdict layers (recursively)
                value           = dotdict( value )
            if '[' in mine and mine[-1] == ']':
                # If indexing used within the final item/attr key, it must encompass the entire
                # final portion of the key; break out the attr[indx], and safely eval it to get the
                # actual index.  Finally, get the object and let it do its own __setitem__.
                mine, indx	= mine.split( '[', 1 )
                indx		= eval( indx[:-1], {'__builtins__':{}}, self )
                dict.__getitem__( self, mine )[indx] = value
            else:
                dict.__setitem__( self, mine, value )

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
            target              = dict.__getitem__( self, mine )
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
                return not isinstance( self.__getitem__( key ), dotdict )
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
                dict.__delitem__( self, mine )
        """
        mine,rest		= self._resolve( key ) if '.' in key else (key,None)
        #logging.debug("del %s, from: %s (in %r)", rest, mine, self )
        # will raise KeyError if no such key...
        target			= self[mine]
        if rest is None:
            # will raise KeyError if partial key (dotdict layer) not empty
            if isinstance( target, dotdict ) and len( target ):
                raise KeyError( 'cannot del "%s" (partial key)' % ( mine ))
            return dict.__delitem__( self, mine )
        del target[rest]

    def pop( self, *args ):
        """Pop doesn't take keyword args, but default is optional.  So, we can only
        override this by capturing args."""
        key			= args[0]
        mine,rest		= self._resolve( key ) if '.' in key else (key,None)
        if rest is None:
            return dict.pop( self, mine, *args[1:] )
        target                  = dict.__getitem__( self, mine )
        if not isinstance( target, dotdict ):
            raise KeyError( 'cannot pop "%s" in "%s" (%r)' % ( rest, mine, target ))
        return target.pop( rest, *args[1:] )

    def setdefault( self, key, default ):
        if key not in self:
            self[key]           = default
        return self[key]

    def get( self, key, default=None ):
        """The default dict.get is not implemented in terms of __getitem__."""
        try:
            return self.__getitem__( key )
        except KeyError:
            return default

    def iteritems( self ):
        """Issue keys for layers of dotdict() in a.b.c... form.  For dotdicts containing a list of
        dotdict, issue keys in a.b[0].c form, since we can handle simple indexes in paths for
        indexing (we'll arbitrarily limit it to just one layer deep)."""
        items			= dict.iteritems if sys.version_info[0] < 3 else dict.items
        for key,val in items( self ):
            if isinstance( val, dotdict ) and val: # a non-empty sub-dotdict layer
                for subkey,subval in val.iteritems():
                    yield key+'.'+subkey, subval
            elif isinstance( val, list ) and val and all( isinstance( subelm, dotdict ) for subelm in val ):
                # Non-empty list of dicts
                subfmt		= "[{subidx:%d}]." % len( str( len( val ) - 1 ))
                for subidx,subelm in enumerate( val ):
                    for subkey,subval in subelm.iteritems():
                        yield key+subfmt.format( subidx=subidx )+subkey, subval
            else: # non-list elements, empty dotdict layers, empty lists
                yield key, val

    def itervalues( self ):
        for key,val in self.iteritems():
            yield val

    def iterkeys( self ):
        for key,val in self.iteritems():
            yield key

    def __listkeys( self ):
        return list( self.iterkeys() )

    def __listvalues( self ):
        return list( self.itervalues() )

    def __listitems( self ):
        return list( self.iteritems() )

    __iter__			= iterkeys
    keys 			= __listkeys   if sys.version_info[0] < 3 else iterkeys
    values			= __listvalues if sys.version_info[0] < 3 else itervalues
    items			= __listitems  if sys.version_info[0] < 3 else iteritems

    def __deepcopy__( self, memo ):
        """Must copy each layer, to avoid copying keys that reference non-existent members."""
        return type( self )( (k,copy.deepcopy( v, memo ))
                             for k,v in dict.items( self ) )

    def __copy__( self ):
        return type( self )( (k,copy.copy( v ))
                             for k,v in dict.items( self ) )


class apidict( dotdict ):
    """A dotdict that ensures that any new values assigned to its attributes are very likely received by
    some other thread (via getattr) before the corresponding setattr returns; setting/getting values
    by indexing (ie. like a normal dict) is *not* affected (except for locking), allowing the user
    to selectively force timeout 'til read on some assignments but not others, and to indicate
    reception of the value on some reads and not others.

    A specified timeout (required as first argument) is enforced after setattr, which is only
    shortened when another thread executes a getattr.

    Note that getting *any* attr on the apidict releases all threads blocked setting *any* attr!
    So, use index access to read the bulk of values, and finally a single getattr to access the last
    value, and indicate completion of access.
    """
    __slots__ = ('_lck', '_cnd', '_tmo')
    def __init__( self, timeout, *args, **kwds ):
        assert isinstance( timeout, (float,int) ), \
            "First argument to apidict must be a numeric timeout"
        object.__setattr__( self, '_lck', threading.RLock() )
        object.__setattr__( self, '_cnd', threading.Condition( self._lck ))
        object.__setattr__( self, '_tmo', timeout )
        super( apidict, self ).__init__( *args, **kwds )

    def __setitem__( self, key, value ):
        with self._cnd:
            super( apidict, self ).__setitem__( key, value )
        
    def __setattr__( self, key, value ):
        with self._cnd:
            super( apidict, self ).__setattr__( key, value )
            self._cnd.wait( self._tmo )

    def __getitem__( self, key ):
        with self._cnd:
            return super( apidict, self ).__getitem__( key )

    def __getattr__( self, key ):
        with self._cnd:
            try:
                return super( apidict, self ).__getattr__( key )
            finally:
                self._cnd.notify_all()
