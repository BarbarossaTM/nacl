#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sun 17 Mar 2019 09:27:09 PM CET
#

import argparse
import sys
from werkzeug.serving import run_simple

from nacl.webservice import NaclWS
from nacl.app import Nacl

# Parse command line arguments
parser = argparse.ArgumentParser (description = 'Netbox Automation and Caching Layer for FFHO Salt')
parser.add_argument ('--config', '-c', help = 'Path to config file (json format)', default = 'nacl_config.json')
parser.add_argument ('--debug', '-D', help = 'Activate werkzeug debugger', action = 'store_true')
parser.add_argument ('--reload', '-R', help = 'Activate werkzeug reloader', action = 'store_true')

args = parser.parse_args ()

# Fire up NACL application
nacl = Nacl (args.config)

# Fire up web service
app = NaclWS (nacl)

try:
	run_simple ('127.0.0.1', 5000, app, use_debugger = args.debug, use_reloader = args.reload)
except Exception as e:
	print ("Failed to start nacld: %s" % e)
