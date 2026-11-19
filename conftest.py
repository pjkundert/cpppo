import sys
from multiprocessing.managers import SyncManager

from .dotdict import apidict, make_apidict_proxy


SyncManager.register(*make_apidict_proxy(apidict))


# The serial suite contains async syntax and uses PyModbus 3.8.
collect_ignore = ['serial_test.py'] if sys.version_info < (3, 9) else []
