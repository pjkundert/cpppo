
import sys

class dotdict(dict):
    """A dict supporting keys containing dots, to access a heirarchy of dicts.
    Furthermore, if the keys form valid attribute names, values are also
    accessible via dotted attribute name access:
    
        >>> d = dotdict()
        >>> d["a.b"] = 1
        >>> d.a.b
        >>> 1

    Every '..' in the key back-tracks by one key element (these ignored elements
    are not checked for validity):

        >>> d['a.x..b'] # same as d['a.b']
        >>> 1
        >>> d['a.x.y...b'] # and works for multiple levels, one dot per level
    """
    def __init__( self, value=None ):
        if value is None:
            pass
        elif isinstance( value, dict ):
            for key, val in value.items():
                self.__setitem__( key, val )
        else:
            raise TypeError( 'expected dict' )

    def _resolve( self, key ):
        """Return next segment in key as (one, rest), solving for any '..'
        back-tracking.  If key begins/ends with ., or too many .. are used, the
        key will end up prefixed by ., 'mine' will end up '', raising KeyError."""
        mine, rest		= key, None
        if '.' in mine:
            while '..' in mine:
                # 'a.b..c'     ==> 'a.c'  ; split == ['a.b',   'c'  ]
                # 'a.b.c...d'  ==> 'a.d'  ; split == ['a.b.c', '.d' ]
                front, back	= mine.split( '..', 1 )
                front		= front[:front.rfind('.')]
                mine		= front + '.' + back
            mine, rest		= mine.split( '.', 1 )
        if not mine:
            raise KeyError('cannot index using key "%s"; no leading path element' % key)
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
            return dict.__getitem__( self, key )
        target                  = dict.__getitem__( self, mine )
        if not isinstance( target, dotdict ):
            raise KeyError( 'cannot get "%s" in "%s" (%r)' % ( rest, mine, target ))
        return target[rest]

    def __contains__( self, key ):
        mine, rest              = self._resolve( key )
        if rest is None:
            return dict.__contains__( self, key )
        target                  = dict.__getitem__( self, mine )
        if not isinstance( target, dotdict ):
            return False
        return rest in target

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

