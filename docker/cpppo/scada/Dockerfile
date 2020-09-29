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
FROM		cpppo/cpppo
LABEL		maintainer="perry@dominionrnd.com"
EXPOSE		44818
ENTRYPOINT	[ "python3", "-m", "cpppo.server.enip" ]
CMD		[ "SCADA=dint[1000]" ]
