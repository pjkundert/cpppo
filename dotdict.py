
import logging
import sys

class dotdict( dict ):
    """A dict supporting keys containing dots, to access a heirarchy of
    dotdicts.  Furthermore, if the keys form valid attribute names, values are
    also accessible via dotted attribute name access:
    
        >>> d = dotdict()
        >>> d["a.b"] = 1
        >>> d.a.b
        >>> 1

    Every '..' in the key back-tracks by one key element (these ignored elements
    are not checked for validity), much like a file-system:

        >>> d['a.x..b']    # same as d['a.b']
        >>> 1
        >>> d['a.x.y...b'] # and works for multiple levels, one dot per level
        >>> 1
        >>> d['a.....a.b'] # and back-tracking past root is OK
        >>> 1

    Any string valid as an attribute name should be valid as a key (leading
    '.' ignored):

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

    but deletion won't allow deleting non-empty levels of the dotdict:

        >>> del d['a']
        Traceback ...
        KeyError: 'cannot del "a" (partial key)'
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

    def __getitem__( self, key ):
        mine, rest              = self._resolve( key )
        if rest is None:
            return dict.__getitem__( self, mine )
        target                  = dict.__getitem__( self, mine )
        if not isinstance( target, dotdict ):
            raise KeyError( 'cannot get "%s" in "%s" (%r)' % ( rest, mine, target ))
        return target[rest]

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
            
    __setattr__			= __setitem__
    __getattr__			= __getitem__

    def iterkeys( self ):
        for key,val in dict.items( self ):
            if isinstance( val, dotdict ):
                # A sub-dotdict; yield all its keys, prefixed with this key
                for subkey in val.iterkeys():
                    yield key + '.' + subkey
            else:
                yield key # Not a sub-dotdict; just yield the key

    def itervalues( self ):
        for key in self.iterkeys():
            yield self[key]

    def iteritems( self ):
        for key in self.iterkeys():
            yield key, self[key]

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

