# cpppo/scada Dockerfile.
#
# DESCRIPTION
#     Built on the base cpppo/cpppo Dockerfile. 
#
# EXAMPLE
#     $ docker build -t cpppo/scada			# or: docker update
#     $ docker run -p 44818:44818 -d cpppo/scada 	# eg. SCADA=dint[1000] ...
# 
#
FROM cpppo/cpppo
MAINTAINER Perry Kundert "perry@hardconsulting.com"
EXPORT 44818
# We'll always run this as our base command
ENTRYPOINT ["python", "-m", "cpppo.server.enip"]
# But we will allow this to be (optionally) overridden
CMD ["SCADA=dint[1000]"]

