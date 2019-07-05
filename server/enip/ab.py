
# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2016, Hard Consulting Corporation.
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

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2016 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

__all__				= ['powerflex', 'powerflex_750_series']

from .get_attribute import proxy_simple

# Example of simple CIP device proxy: AB PowerFlex AC controllers
class powerflex( proxy_simple ):
    pass


class powerflex_750_series( powerflex ):
    """Specific parameters and their addresses, for the PowerFlex 750 Series AC drives."""
    PARAMETERS			= dict( powerflex.PARAMETERS,
        output_frequency	= powerflex.parameter( '@0x93/  1/10',	'REAL',	'Hz' ),
        output_freq 		= powerflex.parameter( '@0x93/  1/10',	'REAL',	'Hz' ),
        mtr_vel_fdbk 		= powerflex.parameter( '@0x93/  3/10',	'REAL',	'Hz/RPM' ), # See = Speed Units
        motor_velocity 		= powerflex.parameter( '@0x93/  3/10',	'REAL',	'Hz/RPM' ), # See = Speed Units
        output_current		= powerflex.parameter( '@0x93/  7/10',	'REAL',	'Amps' ),
        output_voltage		= powerflex.parameter( '@0x93/  8/10',	'REAL',	'VAC' ),
        output_power		= powerflex.parameter( '@0x93/  9/10',	'REAL',	'kW' ),
        dc_bus_volts		= powerflex.parameter( '@0x93/ 11/10',	'REAL',	'VDC' ),
        elapsed_mwh		= powerflex.parameter( '@0x93/ 13/10',	'REAL',	'MWh' ),
        elapsed_kwh		= powerflex.parameter( '@0x93/ 14/10',	'REAL',	'kWh' ),
        elapsed_run_time	= powerflex.parameter( '@0x93/ 15/10',	'REAL',	'Hrs' ),
        rated_volts		= powerflex.parameter( '@0x93/ 20/10',	'REAL',	'VAC' ),
        rated_amps		= powerflex.parameter( '@0x93/ 21/10',	'REAL',	'Amps' ),
        rated_kw		= powerflex.parameter( '@0x93/ 22/10',	'REAL',	'kW' ),
        speed_units		= powerflex.parameter( '@0x93/300/10',	'DINT',	'Hz/RPM' ), # 0-->Hz, 1-->RPM
    )
