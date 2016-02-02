#!/usr/bin/env python

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
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

__all__				= ['attribute_operations', 'proxy', 'proxy_simple', 'main']


"""Deprecated due to name 'getattr', which is also the naem of a built-in method."""

import warnings
import sys

warnings.warn(
    "cpppo.server.enip.getattr deprecated; use cpppo.server.enip.get_attribute instead",
    PendingDeprecationWarning )

from .get_attribute import attribute_operations, proxy, proxy_simple, main

if __name__ == "__main__":
    sys.exit( main() )
