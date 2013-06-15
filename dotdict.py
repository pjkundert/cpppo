
import logging
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
    def __init__( self, *args, **kwds ):
        """Load from args, update from kwds"""
        dict.__init__( self )
        if args:
            for key, val in dict( *args ).items():
                self.__setitem__( key, val )
        if kwds:
            for key, val in kwds.items():
                self.__setitem__( key, val )

    def _resolve( self, key ):
        """Return next segment in key as (mine, rest), solving for any '..'
        back-tracking.  If key begins/ends with ., or too many .. are used, the
        key will end up prefixed by ., 'mine' will end up '', raising KeyError."""
        mine, rest		= key, None
        # Process '..' back-tracking
        #     'a.b..c'     ==> 'a.c'  ; split == ['a.b',   'c'  ]
        #     'a.b.c...d'  ==> 'a.d'  ; split == ['a.b.c', '.d' ]
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
                        logging.info( '_resolve unbalanced %r.%r"' % ( mine, rest ))
                        if not rest:
                            raise KeyError( "unbalance brackets in %s" % key )
                        ext,rest= rest.split( '.', 1 )
                        mine   += '.' + ext
                break
            mine		= rest
        if not mine:
            raise KeyError('cannot resolve "%s" in "%s" from key "%s"' % ( rest, mine, key ))
   
        return mine, rest

    def __setitem__( self, key, value ):
        mine, rest          	= self._resolve( key )
        if rest:
            target              = dict.setdefault( self, mine, dotdict() )
            if not isinstance( target, dotdict ):
                raise KeyError( 'cannot set "%s" in "%s" (%r)' % ( rest, mine, target ))
            target[rest]        = value
        else:
            if isinstance( value, dict ) and not isinstance( value, dotdict ):
                value           = dotdict( value )
            dict.__setitem__( self, key, value )

    __setattr__			= __setitem__

    def __getitem__( self, key ):
        """Locate an item by key: either via indexing, or attribute access:

           <dotdict>['name']
           <dotdict>.name

        If we find something like 'name[1]' or 'name[a.b[c+3]]', etc: resolve it allowing no access
        globals or builtin functions, and only our own dotdict as locals: cannot index using values
        from higher levels of the dotdict, eg. 'name[..above]'

        Note also that the hasattr builtin used getattr to identify the existence of attributes; it
        must return AttributeError if the attribute doesn't exist.
        """
        mine, rest              = self._resolve( key )
        if '[' in mine:
            target              = eval( mine, {'__builtins__':{}}, self )
        else:
            target              = dict.__getitem__( self, mine )
        if rest is None:
            return target
        # We have the rest of the levels to go; must have addressed another dotdict level (or
        # something else that is subscriptable). 
        if not hasattr( target, '__getitem__' ):
            raise KeyError( 'cannot get "%s" in "%s" (%r); not subscriptable' % ( rest, mine, target ))
        return target[rest]

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
        mine, rest		= self._resolve( key )
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
        mine, rest              = self._resolve( key )
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
        items			= dict.iteritems if sys.version_info.major < 3 else dict.items
        for key,val in items( self ):
            if isinstance( val, dotdict ):
                for subkey,subval in val.iteritems():
                    yield key+'.'+subkey, subval
            elif isinstance( val, list ) and all( isinstance( subelm, dotdict ) for subelm in val ):
                for subidx,subelm in enumerate( val ):
                    for subkey,subval in subelm.iteritems():
                        yield key+'['+str(subidx)+'].'+subkey, subval
            else:
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
    keys 			= __listkeys   if sys.version_info.major < 3 else iterkeys
    values			= __listvalues if sys.version_info.major < 3 else itervalues
    items			= __listitems  if sys.version_info.major < 3 else iteritems

