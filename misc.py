
# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2013, Hard Consulting Corporation.
# 
# Cpppo is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.  See the LICENSE file at the top of the source tree.
# 
# Cpppo is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 

from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import functools
import logging
import math
import sys
import time
import types

try:
    import reprlib
except ImportError:
    import repr as reprlib

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

"""
Miscellaneous functionality used by various other modules.
"""

# 
# misc.mutexmethod -- apply a synchronization mutex around a method invocation
# 
def mutexmethod( mutex='lock', blocking=True ):
    """A method synchronization decorator.  Defaults to acquire the mutex attribute (default:
    '<self>.lock') on the class/instance of the bound 'method' during its invocation.  If not
    'blocking', will raise an AssertionError if the mutex cannot be acquired instead of blocking.

    Find the specified lock attribute (may be supplied by the instance or the class, as appropriate)
    and acquire it around the method invocation.  Supports bound instance or class methods only.  We
    use the direct acquire/release interface, because we support optional non-blocking exclusion.

    """
    def decorator( method ):
        def wrapper( *args, **kwds ):
            # Get the class method's class, or the instance method's self argument, then find mutex
            lock		= getattr( getattr( method, '__self__', args[0] ), mutex )
            assert lock.acquire( blocking ), "Lock is held"
            try:
                return method( *args, **kwds )
            finally:
                lock.release()
        return wrapper
    return decorator


# 
# misc.timer
# 
# Select platform appropriate timer function
# 
if sys.platform == 'win32':
    # On Windows, the best timer is time.clock
    timer 			= time.clock
else:
    # On most other platforms the best timer is time.time
    timer			= time.time

# 
# misc.nan	-- IEEE NaN (Not a Number)
# misc.isnan	-- True iff the provided value is nan
# misc.inf	-- IEEE inf (Infinity)
# misc.isinf	-- True iff the provided value is inf
# 
#     Augment math with some useful constants.  Note that IEEE NaN is the
# only floating point number that won't equal itself.
# 
#     Numpy has these, but we can't assume it is available.
# 
if hasattr( math, 'nan' ):
    nan                         = math.nan
else:
    nan                         = float( 'nan' )
    math.nan                    = nan
if hasattr( math, 'isnan' ):
    isnan                       = math.isnan
else:
    def isnan( f ):
        return f != f
    math.isnan			= isnan

if hasattr( math, 'inf' ):
    inf				= math.inf
else:
    inf				= float( 'inf' )
    math.inf			= inf
if hasattr( math, 'isinf' ):
    isinf			= math.isinf
else:
    def isinf( f ):
        return abs( f ) == inf
    math.isinf			= isinf

def change_function( function, **kwds ):
    """Change a function with one or more changed co_... attributes, eg.:

            change_function( func, co_filename="new/file/path.py" )

    will change the func's co_filename to the specified string.

    The types.CodeType constructor differs between Python 2 and 3; see
    type help(types.CodeType) at the interpreter prompt for information:

    Python2:
        code(argcount,                nlocals, stacksize, flags, codestring,
         |        constants, names, varnames, filename, name, firstlineno,
         |        lnotab[, freevars[, cellvars]])

    Python3:
        code(argcount, kwonlyargcount, nlocals, stacksize, flags, codestring,
         |        constants, names, varnames, filename, name, firstlineno,
         |        lnotab[, freevars[, cellvars]])


    """
    # Enumerate  all the __code__ attributes in the same order; types.CodeTypes
    # doesn't accept keyword args, only position.
    attrs			= [ "co_argcount" ]
    if sys.version_info[0] >= 3:
        attrs		       += [ "co_kwonlyargcount" ]
    attrs		       += [ "co_nlocals",
                                    "co_stacksize",
                                    "co_flags",
                                    "co_code",
                                    "co_consts",
                                    "co_names",
                                    "co_varnames",
                                    "co_filename",
                                    "co_name",
                                    "co_firstlineno",
                                    "co_lnotab",
                                    "co_freevars",
                                    "co_cellvars" ]

    assert all( k in attrs for k in kwds ), \
        "Invalid function keyword(s) supplied: %s" % ( ", ".join( kwds.keys() ))

    # Alter the desired function attributes, and update the function's __code__
    modi_args			= [ kwds.get( a, getattr( function.__code__, a )) for a in attrs ]
    modi_code			= types.CodeType( *modi_args )
    modi_func			= types.FunctionType( modi_code, function.__globals__ )
    function.__code__		= modi_func.__code__

# 
# logging.normal	-- regular program output 
# logging.detail	-- detail in addition to normal output
# logging.trace		-- logs less relevant than debug (eg. multiline logs)
# 
#     Augment logging with some new levels, between INFO and WARNING, used for normal/detail output.
# 
#     Unfortunationly, logging uses a fragile method to find the logging function's name in the call
# stack; it looks for the first function whose co_filename is *not* the logger source file.  So, we
# need to change our functions to appear as if they originated from logging._srcfile.
# 
#      .FATAL 		       == 50
#      .ERROR 		       == 40
#      .WARNING 	       == 30
logging.NORMAL			= logging.INFO+5
logging.DETAIL			= logging.INFO+3
#      .INFO    	       == 20
#      .DEBUG    	       == 10
logging.TRACE			= logging.NOTSET+5
#      .NOTSETG    	       == 0

logging.addLevelName( logging.NORMAL,	'NORMAL' )
logging.addLevelName( logging.DETAIL,	'DETAIL' )
logging.addLevelName( logging.TRACE,	'TRACE' )

def __normal( self, msg, *args, **kwargs ):
    if self.isEnabledFor( logging.NORMAL ):
        self._log( logging.NORMAL, msg, args, **kwargs )

def __detail( self, msg, *args, **kwargs ):
    if self.isEnabledFor( logging.DETAIL ):
        self._log( logging.DETAIL, msg, args, **kwargs )

def __trace( self, msg, *args, **kwargs ):
    if self.isEnabledFor( logging.TRACE ):
        self._log( logging.TRACE, msg, args, **kwargs )

change_function( __normal, co_filename=logging._srcfile )
change_function( __detail, co_filename=logging._srcfile )
change_function( __trace, co_filename=logging._srcfile )

logging.Logger.normal		= __normal
logging.Logger.detail		= __detail
logging.Logger.trace		= __trace

def __normal_root( msg, *args, **kwargs ):
    if len( logging.root.handlers ) == 0:
        logging.basicConfig()
    logging.root.normal( msg, *args, **kwargs )

def __detail_root( msg, *args, **kwargs ):
    if len( logging.root.handlers ) == 0:
        logging.basicConfig()
    logging.root.detail( msg, *args, **kwargs )

def __trace_root( msg, *args, **kwargs ):
    if len( logging.root.handlers ) == 0:
        logging.basicConfig()
    logging.root.trace( msg, *args, **kwargs )

change_function( __normal_root, co_filename=logging._srcfile )
change_function( __detail_root, co_filename=logging._srcfile )
change_function( __trace_root, co_filename=logging._srcfile )
logging.normal			= __normal_root
logging.detail			= __detail_root
logging.trace			= __trace_root

# 
# function_name -- Attempt to elaborate on the module/class heritage of the given function
#
def function_name( f ):
    if hasattr( f, '__module__' ):
        return f.__module__ + '.' + f.__name__
    elif hasattr( f, 'im_class' ):
        return f.im_class.__module__ + '.' + f.im_class.__name__ + '.' + f.__name__
    return f.__name__
    
# 
# near          -- True iff the specified values are within 'significance' of each-other
# 
def near( a, b, significance = 1.0e-4 ):
    """ Returns True iff the difference between the values is within the factor 'significance' of
    one of the original values.  Default is to within 4 decimal places. """
    return abs( a - b ) <= significance * max( abs( a ), abs( b ))

# 
# clamp         -- Clamps a value to within a tuple of limits.
# 
#     Limits that are math.nan are automatically ignored, with no special code (comparisons
# against NaN always return False).
# 
#     The ordering of 'lim' is assumed to be (min, max).  We don't attempt to reorder, because 'lim'
# may contain NaN.
# 
def clamp( val, lim ):
    """ Limit val to between 2 (optional, if nan) limits """
    if ( val < lim[0] ):
        return lim[0]
    if ( val > lim[1] ):
        return lim[1]
    return val

# 
# scale         -- Transform a value from one range to another, without clipping
#
#     No math.nan allowed or zero-sized domains or ranges.  Works for either increasing or
# decreasing ordering of domains or ranges.  If clamped, we will ensure that the rng is (re)ordered
# appropriately.
# 
#     If non-unity exponent is provided, then the input domain is raised to the appropriate power
# during the mapping.  This allows us to map something like (25,40)->(0,1) with a curve such as:
# 
#   1 |              .
#     |             .
#     |           ..
#     |        ...
#     |   .....
#   0 +---------------
#     2              4
#     5              0
# 
def scale( val, dom, rng, clamped=False, exponent=1 ):
    """Map 'val' from domain 'dom', to new range 'rng', optionally with an exponential scaling.  If a
    non-unity exponent is provided, then the input value is also clamped to the input domain (and
    its order is asserted) since raising -'ve values to arbitrary exponents will usually have very
    unexpected results.  Otherwise, at unity exponent, allow -'ve values and out-of-order ranges.

    """
    if exponent != 1:
        assert dom[1] > dom[0], "Scaling %s non-linearly requires an ordered domain: %s" % ( val, dom )
        if clamped:
            val			= clamp( val, (min(dom),max(dom)) )
        else:
            assert dom[0] <= val <= dom[1], "Scaling %s non-linearly requires value in domain: %s" % ( val, dom )
    else:
        assert dom[1] != dom[0], "Scaling %s requires a non-zero domain: %s" % ( val, dom )
    result                      = ( rng[0]
                                    + ( val    - dom[0] ) ** exponent
                                    * ( rng[1] - rng[0] )
                                    / ( dom[1] - dom[0] ) ** exponent )
    if clamped:
        result                  = clamp( result, (min(rng),max(rng)))
    return result

# 
# magnitude     -- Return the approximate base magnitude of the value, in 'base' ( 10 )
#
#     Handy for computing up/down modifiers for values.  For example:
#
#      23 ==> 1.
#     .23 ==>  .1
# 
# The magnitude shifts to the next higher value about 1/4 of the way
# past each multiple of base.
# 
def magnitude( val, base = 10 ):
    if val <= 0:
        return nan
    return pow( base, round( math.log( val, base )) - 1 )

# 
# exponential_moving_average -- rolling average without any data history
#
#
# Computes an exponential moving average:
#
#     ( 1 - weight ) * current + weight * sample
#
# where the incoming sample has the given weight, and current samples have exponentially less
# influence on the current value.  Ignores a current value of None.
# 
def exponential_moving_average( current, sample, weight ):
    return sample if current is None else current + weight * ( sample - current )

# 
# reprargs(args,kwds)	-- log args/kwds in sensible fashion
# @logresult(prefix,log)-- decorator to log results/exception of function
# lazystr		-- lazily evaluate expensive string formatting
# 
def reprargs( *args, **kwds ):
    return ", ".join(   [ reprlib.repr( x ) for x in args ]
                      + [ "%s=%s" % ( k, reprlib.repr( v ))
                          for k,v in kwds.items() ])


def logresult( prefix=None, log=None, log_level=logging.DEBUG, exc_level=logging.WARNING, exc_swallow=False ):
    def decorator( function ):
        @functools.wraps( function )
        def wrapper( *args, **kwds ):
            try:
                result		= function( *args, **kwds )
                if ( log or logging.getLogger() ).isEnabledFor( log_level ):
                    ( log or logging ).log( log_level, "%s-->%r" % (
                        prefix or function.__name__+'('+reprargs( *args, **kwds )+')', result ))
                return result
            except (GeneratorExit,StopIteration) as exc:
                if ( log or logging.getLogger() ).isEnabledFor( exc_level ):
                    ( log or logging ).log( exc_level, "%s-->%r" % (
                        prefix or function.__name__+'('+reprargs( *args, **kwds )+')', exc ))
                raise
            except Exception as exc:
                if ( log or logging.getLogger() ).isEnabledFor( exc_level ):
                    ( log or logging ).log( exc_level, "%s-->%r" % (
                        prefix or function.__name__+'('+reprargs( *args, **kwds )+')', exc ))
                if not exc_swallow:
                    raise
        return wrapper
    return decorator


class lazystr( object ):
    """Evaluates the given function returning a str lazily, eg:
           logging.debug( lazystr( lambda: \
               "Some expensive operation: %d" % ( obj.expensive() )))
       vs.:
           logging.debug(
               "Some expensive operation: %d", obj.expensive() )
    """
    __slots__ = '_function'
    def __init__( self, function ):
        self._function		= function
    def __str__( self ):
        return self._function()


# 
# sort order key=... methods
# 
# natural	-- Strings containing numbers sort in natural order
# nan_first	-- NaN/None sorts lower than any number
# nan_last	-- NaN/None sorts higher than any number
# 
# 
def natural( string, fmt="%9s", ):
    '''A natural sort key helper function for sort() and sorted() without using
    regular expressions or exceptions. 

    In python2, incomparable types (eg. str and bool) were compared based on
    (arbitrary) conventions (eg. type name, object ID).  In Python3,
    incomparable types raise exceptions.  So, all types must be converted to a
    common comparable type; str, and non-numeric types are 

    >>> items = ('Z', 'a', '10th', '1st', '9')
    >>> sorted(items)
    ['10th', '1st', '9', 'Z', 'a']
    >>> sorted(items, key=natural)
    ['1st', '9', '10th', 'a', 'Z']    
    '''
    if type( string ) in natural.num_types:
        # Convert numerics to string; sorts 9.3 and '9.3' as equivalent
        string = str(string)
    if not isinstance( string, natural.str_type ):
        # Convert remaining types compare as ('',<type name>,<hash>/<id>), to
        # sorts objects of same type in an orderly fashion.   If __has__ exists
        # but is None, indicates not hash-able.
        res = ('', string.__class__.__name__, 
               hash( string ) if hasattr( string, '__hash__' ) and string.__hash__ is not None
               else id( string ))
    else:
        res = []
        for c in string:
            if c.isdigit():
                if res and type( res[-1] ) in natural.num_types:
                    res[-1] = res[-1] * 10 + int( c )
                else:
                    res.append( int( c ))
            else:
                res.append( c.lower() )
    return tuple( (( fmt % itm ) if type( itm ) in natural.num_types
                   else itm )
                  for itm in res )

natural.str_type 	= ( basestring if sys.version_info[0] < 3
                            else str )
natural.num_types	= ( (float, int, long) if sys.version_info[0] < 3
                            else (float, int))


def non_value( number ):
    return number is None or isnan( number )

def nan_first( number ):
    if non_value( number ):
        return -inf
    return number

def nan_last( number ):
    if non_value( number ):
        return inf
    return number

# 
# centeraxis	-- center string in width around a (rightmost) axis character
# 
def centeraxis( string, width, axis='.', fillchar=' ', reverse=False, clip=False,
                left_right=lambda w: (w // 2, w - w // 2) ):
    string		= str( string )
    pos			= string.find( axis ) if reverse else string.rfind( axis )
    if pos < 0:
        # No axis cahr
        if reverse:
            pos, string	= len( string ), string
        else:
            # ... but it would normally be on the right
            pos, string	= 0,             fillchar + string
    left, rght		= string[0:pos], string[pos:] # axis char will be on rght
    lwid, rwid		= left_right( width )
    #print("left: %s (%d), rght: %s (%d)" % ( left, lwid, rght, rwid ))
    if len( left ) < lwid:
        left		= fillchar * ( lwid - len( left )) + left
    elif clip:
        left		= left[-lwid:]
    if len( rght ) < rwid:
        rght	       += fillchar * ( rwid - len( rght ))
    elif clip:
        rght		= rght[:rwid]
    return left+rght


def assert_tps( minimum=None, scale=None, repeat=1 ):
    """Decorator that asserts a minimum TPS rate.  Optionally, scaled by the specified known number
    of repetitions per call (if scale is numeric, or supplied as the named keyword).  If repeat
    is given, execute function the specified number of repetitions (and adjust scale
    accordingly).

    """
    def decorator( function ):
        @functools.wraps( function )
        def wrapper( *args, **kwds ):
            beg			= timer()
            cnt			= repeat
            while cnt:
                cnt 	       -= 1
                result		= function( *args, **kwds )
            dur			= timer() - beg
            spt			= dur / repeat
            sca			= scale
            if not isinstance( sca, (int,float) ):
                sca		= 1 if sca is None else kwds[sca]
            tps			= float( sca ) / spt
            logging.warning( "Performance: %7.3f TPS (%d x %s)" % ( 
                tps, repeat * sca, function_name( function )))
            if minimum is not None:
                assert tps >= minimum, "Performance below minimum %7.3f TPS: %7.3f (%d x %s)" % (
                    minimum, tps, repeat, function_name( function ))
            return result
        return wrapper
    return decorator



