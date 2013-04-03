class dotdict(dict):
    """A dict supporting keys containing dots, to access a heirarchy of dicts.
    Furthermore, if the keys form valid attribute names, also accessible by
    dotted attribute names:
    
        >>> d = dotdict()
        >>> d["a.b"] = 1
        >>> d.a.b
        >>> 1
    """
    def __init__( self, value=None ):
        if value is None:
            pass
        elif isinstance( value, dict ):
            for key, val in value.items():
                self.__setitem__( key, val )
        else:
            raise TypeError( 'expected dict' )

    def __setitem__( self, key, value ):
        if '.' in key:
            mine, rest          = key.split( '.', 1 )
            target              = dict.setdefault( self, mine, dotdict() )
            if not isinstance( target, dotdict ):
                raise KeyError( 'cannot set "%s" in "%s" (%r)' % ( rest, mine, target ))
            target[rest]        = value
        else:
            if isinstance( value, dict ) and not isinstance( value, dotdict ):
                value           = dotdict( value )
            dict.__setitem__( self, key, value )

    def __getitem__( self, key ):
        if '.' not in key:
            return dict.__getitem__( self, key )
        mine, rest              = key.split( '.', 1 )
        target                  = dict.__getitem__( self, mine )
        if not isinstance( target, dotdict ):
            raise KeyError( 'cannot get "%s" in "%s" (%r)' % ( rest, mine, target ))
        return target[rest]

    def __contains__( self, key ):
        if '.' not in key:
            return dict.__contains__( self, key )
        mine, rest              = key.split( '.', 1 )
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
            
    __setattr__ = __setitem__
    __getattr__ = __getitem__
