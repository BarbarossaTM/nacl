#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Fri 15 Feb 2019 09:04:27 PM CET
#

import argparse
import json
import os
import redis

import netbox
from netbox import NetboxError

from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, BadRequest, NotFound, MethodNotAllowed, InternalServerError

config = None

endpoints = {
	'/' : {
		'call' : 'help',
	},

	# SSH
	'/ssh/register_key' : {
		'call' : 'ssh_register_key',
		'args' : ['request/remote_addr', 'POST/key_type', 'POST/key'],
	},
}

valid_arg_types = ['request', 'GET', 'POST']


class NaclError (Exception): {}
class DeveloperError (InternalServerError): {}


class NaclWS (object):
	def __init__ (self, config):
		self.nacl = Nacl (config)

		# Build URL map
		rules = []

		for url in sorted (endpoints):
			# Use the URL and endpoint to be able to fetch config in dispatch_request()
			rules.append (Rule (url, endpoint = url))

		self.url_map = Map (rules)


	def dispatch_request (self, request):
		adapter = self.url_map.bind_to_environ (request.environ)
		try:
			endpoint, values = adapter.match ()

			# HAS to be present, otherwise we wouldn't be here
			endpoint_config = endpoints[endpoint]

			# Prepare arguments to give to the endpoint as *args
			args = self._prepare_args (request, endpoint, endpoint_config)

			try:
				func_h = getattr (self.nacl, endpoint_config['call'])
				res = func_h (*args)
				return Response (res)
			except NetboxError as n:
				return BadRequest (description = str (n))
			except NaclError as n:
				return BadRequest (description = str (n))
			except Exception as n:
				return InternalServerError (description = str (n))
		except HTTPException as e:
			return e


	def _prepare_args (self, request, endpoint, endpoint_config):
		args = []

		# If this endpoint does not require any args were done already, yay.
		if 'args' not in endpoint_config:
			return args

		try:
			for arg_config in endpoint_config['args']:
				arg_type, arg_name = arg_config.split ('/')

				args.append (self._get_arg (request, arg_type, arg_name, endpoint))
		except ValueError:
			raise DeveloperError ("Invalid argument config '%s' for endpoint '%s'." % (arg_config, endpoint))

		return args


	def _get_arg (self, request, arg_type, arg_name, endpoint):
		if arg_type not in valid_arg_types:
			raise DeveloperError ("Invalid argument type '%s' for argument '%s' for endoint '%s'." % (arg_type, arg_name, endpoint))

		if arg_type in ['GET', 'POST']:
			if request.method != arg_type:
				raise MethodNotAllowed (valid_methods = arg_type, description = "%s call expected." % arg_type)
			try:
				if arg_type == "GET":
					return request.args[arg_name]
				elif arg_type == "POST":
					return request.form[arg_name]
			except KeyError:
				raise BadRequest (description = "Expected GET param '%s'" % param)

		if arg_type == "request":
			try:
				return getattr (request, param)
			except Exception:
				raise HTTPException (description = "Invalid request param '%s' configured. Please hit the developer with a clue bat." % param)


	def wsgi_app (self, environ, start_response):
		request = Request (environ)
		response = self.dispatch_request (request)

		return response (environ, start_response)


	def __call__ (self, environ, start_response):
		return self.wsgi_app (environ, start_response)


class Nacl (object):
	def __init__ (self, config_file):
		self._read_config (config_file)

		self.redis = redis.Redis (self.config['redis_host'], self.config['redis_port'])
		self.netbox = netbox.Netbox (self.config['netbox'])


	def _read_config (self, config_file):
		try:
			with open (config_file, 'r') as config_fh:
				self.config = json.load (config_fh)
		except IOError as i:
			raise NaclError ("Failed to read config from '%s': %s" % (config_file, str (i)))


	#
	# Endpoints
	#
	def help (self):
		return "Welcome to Nacl!"


	# Register given ssh key of given type for device with given IP if none is already present
	def register_ssh_key (self, ip, key_type, key):
		node = self.netbox.get_node_by_ip (ip)

		if not node:
			raise NaclError ("No node found for IP '%s'." % ip)

		if self.netbox.get_node_ssh_key (node[0], node[1], key_type):
			raise NaclError ("Key of type '%s' already present for node '%s'!" % (key_type, ip))

		return self.netbox.set_node_ssh_key (node[0], node[1], key_type, key)



def create_app ():
	app = NaclWS (config)

#	if with_static:
#		app.wsgi_app = SharedDataMiddleware(app.wsgi_app, {
#            '/static':  os.path.join(os.path.dirname(__file__), 'static')
#        })

	return app

if __name__ == '__main__':

	parser = argparse.ArgumentParser (description = 'Netbox Automation and Caching Layer for FFHO Salt')
	parser.add_argument ('--config', '-c', help = 'Path to config file (json format)', default = 'nacl_config.json')
	args = parser.parse_args ()

	from werkzeug.serving import run_simple

	app = NaclWS (args.config)
	run_simple ('127.0.0.1', 5000, app, use_debugger = True, use_reloader = True)
