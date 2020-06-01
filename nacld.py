#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sun 17 Mar 2019 09:27:09 PM CET
#

import argparse
import logging
import sys
from werkzeug.serving import run_simple

from nacl.webservice import NaclWS
from nacl.app import Nacl

# Parse command line arguments
parser = argparse.ArgumentParser (description = 'Netbox Automation and Caching Layer for FFHO Salt')
parser.add_argument ('--config', '-c', help = 'Path to config file (json format)', default = 'nacl_config.json')
parser.add_argument ('--debug', '-D', help = 'Activate werkzeug debugger', action = 'store_true')
parser.add_argument ('--reload', '-R', help = 'Activate werkzeug reloader', action = 'store_true')
parser.add_argument ('--listen', help = 'Local address to listen on.', default = '127.0.0.1')
parser.add_argument ('--port', help = "TCP port to listen on.", default = '5000', type = int)
parser.add_argument ('--log-level', help = "Log level", choices = ['debug', 'info', 'warning', 'error', 'critical'], default = 'info')
parser.add_argument ('--log-file', help = "Path to log file, - for stdout (default)", default = '-')

args = parser.parse_args ()

#
# Set up logging
#

def setup_logging (args):
	# Fire up a logger for NACL and one which will be used by werkzeug
	nacl = logging.getLogger ('nacl')

	# Log level?
	level_map = {
		'debug' : logging.DEBUG,
		'info' : logging.INFO,
		'warning' : logging.WARNING,
		'error' : logging.ERROR,
		'critical' : logging.CRITICAL,
	}

	# Set NACL log level
	nacl.setLevel (level_map[args.log_level])

	# Where to log to?
	if args.log_file == '-':
		handler = logging.StreamHandler ()
	else:
		handler = logging.FileHandler (args.log_file)

	# Log format
	formatter = logging.Formatter ('%(asctime)s %(levelname)s %(message)s')
	handler.setFormatter (formatter)

	nacl.addHandler (handler)

	return nacl

#
# Let's go
#
log = setup_logging (args)
log.info ("NACL starting...")

# Fire up NACL application
nacl = Nacl (args.config)

# Fire up web service
app = NaclWS (nacl)

try:
	run_simple (args.listen, args.port, app, use_debugger = args.debug, use_reloader = args.reload)
except Exception as e:
	print ("Failed to start nacld: %s" % e)
