# cpppo/scada Dockerfile.
#
# DESCRIPTION
#     A simple simulated Logix Controller, built on the base cpppo/cpppo Dockerfile.
#
# EXAMPLE
#
#     Run the Controller containing the default tag SCADA consisting of 1000
# 16-bit DINTs (add your own, instead of the default):
#
#   $ docker run -p 44818:44818 -d cpppo/scada 		# eg. SCADA=dint[1000] ...
#
#     Update the image, and push it up to index.docker.io (unless you own the
# cpppo account, change the name to your own docker.io account):
#
#   $ docker build -t cpppo/scada			# or: make update
#
FROM		cpppo/cpppo
MAINTAINER	Perry Kundert "perry@hardconsulting.com"
EXPORT		44818
# We'll always run this as our base command
ENTRYPOINT	["python", "-m", "cpppo.server.enip"]
# But we will allow this to be (optionally) overridden
CMD		["SCADA=dint[1000]"]
