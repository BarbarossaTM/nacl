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
from werkzeug.exceptions import HTTPException, BadRequest, NotFound, MethodNotAllowed

config = None

endpoints = {
	'/' : {
		'call' : 'help',
	},

	# SSH
	'/ssh/register_key' : {
		'call' : 'ssh_register_key',
		'post_params' : ['key_type', 'key'],
		'request_params' : ['remote_addr'],
	},
}

class NaclError (Exception): {}


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

			args = {}

			if 'post_params' in endpoint_config:
				args['post_params'] = self._gather_POST_params (request, endpoint_config['post_params'])

			request_params = None
			if 'request_params' in endpoint_config:
				args['request_params'] = self._get_request_params (request, endpoint_config['request_params'])


			try:
				res = getattr (self, 'on_' + endpoint_config['call'])(request, **values, **args)
				return Response (res)
			except NetboxError as n:
				return BadRequest (description = str (n))
			except NaclError as n:
				return BadRequest (description = str (n))
			except Exception as n:
				return BadRequest (description = str (n))
		except HTTPException as e:
			return e


	def _gather_POST_params (self, request, params):
		if request.method != 'POST':
			raise MethodNotAllowed (valid_methods = "POST", description = "POST call expected")

		post_params = {}
		for param in params:
			try:
				post_params[param] = request.form[param]
			except KeyError:
				raise BadRequest (description = "Expected POST param '%s'" % param)
		return post_params


	def _get_request_params (self, request, params):
		request_params = {}

		for param in params:
			try:
				request_params[param] = getattr (request, param)
			except Exception:
				raise HTTPException (description = "Invalid request param '%s' configured. Please hit the developer with a clue bat." % param)

		return request_params


	def wsgi_app (self, environ, start_response):
		request = Request (environ)
		response = self.dispatch_request (request)

		return response (environ, start_response)


	def __call__ (self, environ, start_response):
		return self.wsgi_app (environ, start_response)

	#
	# Endpoints
	#

	def on_help (self, request):
		return Response ("Welcome to Nacl!")

	def on_ssh_register_key (self, request, request_params, post_params):
		return self.nacl.register_ssh_key (request_params['remote_addr'], post_params['key_type'], post_params['key'])


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
