"""
Example of using cpppo.server.enip EtherNet/IP CIP client API.

To see the Tag operations succeed, fire up:
    python -m cpppo.server.enip Tag=DINT[10]
"""
import sys, logging
import cpppo
from cpppo.server.enip import address, client

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )
    #logging.getLogger().setLevel(logging.INFO)
    host			= 'localhost'	# Controller IP address
    port			= address[1]	# default is port 44818
    depth			= 1		# Allow 1 transaction in-flight
    multiple			= 0		# Don't use Multiple Service Packet
    fragment			= False		# Don't force Read/Write Tag Fragmented
    timeout			= 1.0		# Any PLC I/O fails if it takes > 1s
    printing			= True		# Print a summary of I/O
    tags			= ["Tag[0-9]+16=(DINT)4,5,6,7,8,9", "@0x2/1/1", "Tag[3-5]"]
    
    with client.connector( host=host, port=port, timeout=timeout ) as connection:
        operations		= client.parse_operations( tags )
        failures,transactions	= connection.process(
            operations=operations, depth=depth, multiple=multiple,
            fragment=fragment, printing=printing, timeout=timeout )
    
    sys.exit( 1 if failures else 0 )
    
