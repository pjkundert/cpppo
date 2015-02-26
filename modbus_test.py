
import errno
import logging
import os
import re
import signal
import subprocess
import time

has_o_nonblock			= False
try:
    import fcntl
    has_o_nonblock		= True
except Exception:
    logging.warning( "Failed to import fcntl; skipping simulated Modbus/TCP PLC tests" )

from . import misc

RTU_WAIT			= 2.0  # How long to wait for the simulator
RTU_LATENCY			= 0.05 # poll for command-line I/O response 

class nonblocking_command( object ):
    """Set up a non-blocking command producing output.  Read the output using:

        collect 		= ''
        while True:
            if command is None:
                # Restarts command on failure, for example
                command 	= nonblocking_command( ... )

            try:
                data 		= command.stdout.read()
                logging.debug( "Received %d bytes from command, len( data ))
                collect        += data
            except IOError as exc:
                if exc.errno != errno.EAGAIN:
                    logging.warning( "I/O Error reading data: %s" % traceback.format_exc() )
                    command	= None
                # Data not presently available; ignore
            except:
                logging.warning( "Exception reading data: %s", traceback.format_exc() )
                command		= None

            # do other stuff in loop...

    The command is killed when it goes out of scope.
    """
    def __init__( self, command ):
        shell			= type( command ) is not list
        self.command		= ' '.join( command ) if not shell else command
        logging.info( "Starting command: %s", self.command )
        self.process		= subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid, shell=shell )

        fd 			= self.process.stdout.fileno()
        fl			= fcntl.fcntl( fd, fcntl.F_GETFL )
        fcntl.fcntl( fd, fcntl.F_SETFL, fl | os.O_NONBLOCK )

    @property
    def stdout( self ):
        return self.process.stdout

    def kill( self ):
        logging.info( 'Sending SIGTERM to PID [%d]: %s', self.process.pid, self.command )
        try:
            os.killpg( self.process.pid, signal.SIGTERM )
        except OSError as exc:
            logging.info( 'Failed to send SIGTERM to PID [%d]: %s', self.process.pid, exc )
        else:
            logging.info( "Waiting for command (PID [%d]) to terminate", self.process.pid )
            self.process.wait()

        logging.info("Command (PID [%d]) finished with status [%d]: %s", self.process.pid, self.process.returncode, self.command )

    __del__			= kill


def start_modbus_simulator( options ):
    command			= nonblocking_command( [
        os.path.join( '.', 'bin', 'modbus_sim.py' ), 
    ] + list( options ))

    begun			= misc.timer()
    address			= None
    data			= ''
    while address is None and misc.timer() - begun < RTU_WAIT:
        # On Python2, socket will raise IOError/EAGAIN; on Python3 may return None 'til command started.
        try:
            raw			= command.stdout.read()
            logging.debug( "Socket received: %r", raw)
            if raw:
                data  	       += raw.decode( 'utf-8' )
        except IOError as exc:
            logging.debug( "Socket blocking...")
            assert exc.errno == errno.EAGAIN, "Expected only Non-blocking IOError"
        except Exception as exc:
            logging.warning("Socket read return Exception: %s", exc)
        if not data:
            time.sleep( RTU_LATENCY )
        while data.find( '\n' ) >= 0:
            line,data		= data.split( '\n', 1 )
            logging.info( "%s", line )
            m			= re.search( "address = (.*)", line )
            if m:
                try:
                    host,port	= m.group(1).split( ':' )
                    address	= host,int(port)
                    logging.normal( "Modbus/TCP Simulator started after %7.3fs on %s:%d",
                                    misc.timer() - begun, address[0], address[1] )
                except:
                    assert m.group(1).startswith( '/' )
                    address	= m.group(1)
                    logging.normal( "Modbus/RTU Simulator started after %7.3fs on %s",
                                    misc.timer() - begun, address )
                break
    return command,address
