import os
import pty
import select
import sys
import termios
import fcntl

N				= int(sys.argv[1]) if len(sys.argv) > 1 else 3
masters				= {}  # <master-fd>: <slave-name>

for n in range(N):
    try:
        os.unlink(f"ttyV{n}")
    except:
        pass
    master, slave		= pty.openpty()
        
    # Configure master end for raw operation
    attrs			= termios.tcgetattr(master)
    # Disable all input/output processing
    attrs[0]			= 0     # iflag
    attrs[1]			= 0     # oflag
    attrs[2]			= 0     # cflag
    attrs[3]			= 0     # lflag
    attrs[6][termios.VMIN]	= 1
    attrs[6][termios.VTIME]	= 0
    termios.tcsetattr( master, termios.TCSANOW, attrs )
        
    masters[master]		= f"ttyV{n}"
    os.symlink( os.ttyname(slave), masters[master] )
    print( f"{masters[master]} -> {os.ttyname(slave)}" )

try:
    while True:
        readable, _, _		= select.select(masters, [], [])
        for i in readable:
            data		= os.read( i, 1024 )
            if data:
                print( f"{len(data)} <-- {masters[i]}: 0x" + "".join( f"{b:02x}" for b in data ))
                for o in masters:
                    if o != i:
                        print( f"{len(data)} --> {masters[o]}" )
                        os.write(o, data)
except KeyboardInterrupt:
    print( f"\nCleaning up {', '.join(masters.values())}..." )
    
finally:
    for symlink in masters.values():
        os.unlink( symlink )
