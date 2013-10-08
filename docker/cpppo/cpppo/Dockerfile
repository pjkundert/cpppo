# cpppo/cpppo Dockerfile.
#
# DESCRIPTION
#     Base cpppo/cpppo Dockerfile.  Use this Docker image in a 'FROM cpppo/cpppo' line
# when building other Dockerfiles based on cpppo.
#
# EXAMPLE
#     $ docker build -t cpppo/cpppo
#     $ docker run -p 44818:44818 -d cpppo/cpppo python -m cpppo.server.enip SCADA=dint[1000]
#
# NOTE
#     Dating the "apt-get update # YYYY-MM-DD" allows us to force a fresh build, and not
# use previously cached Docker images produced from older builds
#
FROM ubuntu:12.04
MAINTAINER Perry Kundert "perry@hardconsulting.com"
RUN sed -e "s|http://[^[:space:]]*|http://mirrors.kernel.org/ubuntu|" -e "s|main$|main universe|" -i /etc/apt/sources.list
RUN cat /etc/apt/sources.list
RUN apt-get update # YYYY-MM-DD
RUN apt-get -yu dist-upgrade
RUN apt-get -y install python python-pip
RUN pip install cpppo
