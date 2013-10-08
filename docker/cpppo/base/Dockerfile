# cpppo/base Dockerfile.
#
# DESCRIPTION
#     Base image for all cpppo/* images.
#
# EXAMPLE
#
#     Build a new image.  Using the GNUmakefile 'update' target updates any '#
# YYYY-MM-DD' dated lines in the Dockerfile so that out-of-date cached images
# won't be used:
#
#   $ docker build -t cpppo/base cpppo/base		# or: make update
#
FROM		ubuntu:12.04
MAINTAINER	Perry Kundert "perry@hardconsulting.com"
RUN		sed -e "s|http://[^[:space:]]*|http://mirrors.kernel.org/ubuntu|" -e "s|main$|main universe|" -i /etc/apt/sources.list
RUN		apt-get update 				# 2013-10-08
RUN		apt-get -yu dist-upgrade
