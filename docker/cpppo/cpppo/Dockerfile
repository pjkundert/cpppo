# cpppo/cpppo Dockerfile.
#
# DESCRIPTION
#     Base cpppo/cpppo Dockerfile.  Use this Docker image in a 'FROM cpppo/cpppo' line
# when building other Dockerfiles based on cpppo.
#
# EXAMPLE
#
#     Come on in and look around:
#
#   $ docker run /bin/bash
#
#     Manually run any cpppo-based service; a simple simulated Logix controller for example:
#
#   $ docker run -p 44818:44818 -d cpppo/cpppo python -m cpppo.server.enip SCADA=dint[1000]
#
#     Build a new image.  Using the GNUmakefile 'update' target updates any '#
# YYYY-MM-DD' dated lines in the Dockerfile so that out-of-date cached images
# won't be used:
#
#   $ docker build -t cpppo/cpppo			# or: make update
#
FROM		ubuntu:12.04
MAINTAINER	Perry Kundert "perry@hardconsulting.com"
RUN		sed -e "s|http://[^[:space:]]*|http://mirrors.kernel.org/ubuntu|" -e "s|main$|main universe|" -i /etc/apt/sources.list
RUN		apt-get update 			# 2013-10-08
RUN		apt-get -yu dist-upgrade
RUN		apt-get -y install python python-pip
RUN		pip install cpppo
