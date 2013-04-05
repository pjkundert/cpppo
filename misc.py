
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


from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "GNU General Public License, Version 3 (or later)"
__version__			= "0.01"

"""
Miscellaneous functionality used by various other modules.
"""

import math
import timeit

# 
# misc.timer
# 
# Select platform appropriate timer function
timer = timeit.default_timer

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
    math.isnan = isnan

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
    math.isinf = isinf

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
def scale( val, dom, rng, clamped=False ):
    """Map 'val' from domain 'dom', to new range 'rng'"""
    result                      = ( rng[0]
                                    + ( val    - dom[0] )
                                    * ( rng[1] - rng[0] )
                                    / ( dom[1] - dom[0] ))
    if clamped:
        result                  = clamp( result, (min(rng), max(rng)))
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

def magnitude( val, base = 10 ):
    if val <= 0:
        return nan
    return pow( base, round( math.log( val, base )) - 1 )


# 
# sort order key=... methods
# 
# natural	-- Strings containing numbers sort in natural order
# nan_first	-- NaN/None sorts lower than any number
# nan_last	-- NaN/None sorts higher than any number
# 
def natural( string ):
    '''
    A natural sort key helper function for sort() and sorted() without
    using regular expressions or exceptions.

    >>> items = ('Z', 'a', '10th', '1st', '9')
    >>> sorted(items)
    ['10th', '1st', '9', 'Z', 'a']
    >>> sorted(items, key=natural)
    ['1st', '9', '10th', 'a', 'Z']    
    '''
    it = type( 1 )
    r = []
    for c in string:
        if c.isdigit():
            d = int( c )
            if r and type( r[-1] ) == it: 
                r[-1] = r[-1] * 10 + d
            else: 
                r.append( d )
        else:
            r.append( c.lower() )
    return r

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
def centeraxis( string, width, axis='.', fillchar=' ', reverse=False, clip=False ):
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
    lwid, rwid		= width // 2, width - width // 2
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
