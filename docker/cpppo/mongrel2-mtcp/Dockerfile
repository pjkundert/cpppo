# -*- mode: conf -*-
# cpppo/mongrel2-mtcp Dockerfile.
#
# DESCRIPTION
#     Support for Modbus/TCP (via pymodbus) PLC simulation, using Mongrel2's
# ZeroMQ WebSockets protocol as the underlying transport.  Also support for 
# other network/interface and IP address manipulations.
#
FROM		cpppo/mongrel2
MAINTAINER	Perry Kundert "perry@hardconsulting.com"

RUN		pip install pymodbus py2-ipaddress netifaces

# Typically supports applications providing remote access via HTTP, Modbus/TCP and EtherNet/IP, eg:
#EXPOSE		80 502 44818
