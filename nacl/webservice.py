#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sun 17 Mar 2019 09:33:00 PM CET
#

import json
from werkzeug.exceptions import HTTPException, BadRequest, NotFound, MethodNotAllowed, InternalServerError
from werkzeug.routing import Map, Rule
from werkzeug.wrappers import Request, Response

from nacl.errors import *

valid_arg_types = ['request', 'GET', 'POST']

endpoints = {
	'/' : {
		'call' : 'help',
		'internal': True,
	},
}


class NaclWS (object):
	def __init__ (self, nacl):
		self.nacl = nacl

		# Build URL map
		rules = []

		# Merge NACL endpoints into ours
		self.endpoints = endpoints
		self.endpoints.update (nacl.get_endpoints ())

		for url in sorted (self.endpoints):
			# Use the URL and endpoint to be able to fetch config in dispatch_request()
			rules.append (Rule (url, endpoint = url))

		self.url_map = Map (rules)


	def dispatch_request (self, request):
		adapter = self.url_map.bind_to_environ (request.environ)
		try:
			endpoint, values = adapter.match ()

			# HAS to be present, otherwise we wouldn't be here
			endpoint_config = self.endpoints[endpoint]

			# Prepare arguments to give to the endpoint as *args
			args = self._prepare_args (request, endpoint, endpoint_config)

			try:
				if endpoint_config.get ('internal', False):
					func_h = getattr (self, "ep_%s" % endpoint_config['call'])
				else:
					func_h = getattr (self.nacl, endpoint_config['call'])

				res = func_h (**args)
				if res:
					res = json.dumps (res)

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
		args = {}

		# If this endpoint does not require any args we're done already, yay.
		if 'args' not in endpoint_config:
			return args

		try:
			for arg_config in endpoint_config['args']:
				arg_type, arg_name = arg_config.split ('/')

				# Is this and optional argument?
				is_optional = False
				if arg_name.endswith ('?'):
					arg_name = arg_name.replace ('?', '')
					is_optional = True

				try:
					args[arg_name] = (self._get_arg (request, arg_type, arg_name, endpoint))
				except BadRequest as b:
					if is_optional:
						continue
					else:
						raise b
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
				raise BadRequest (description = "Expected %s param '%s'" % (arg_type, arg_name))

		if arg_type == "request":
			try:
				return getattr (request, arg_name)
			except Exception:
				raise HTTPException (description = "Invalid request param '%s' configured. Please hit the developer with a clue bat." % arg_name)


	def wsgi_app (self, environ, start_response):
		request = Request (environ)
		response = self.dispatch_request (request)

		return response (environ, start_response)


	def __call__ (self, environ, start_response):
		return self.wsgi_app (environ, start_response)

	#
	# Internal endpoints
	#

	def ep_help (self):
		return "Welcome to NACL!"
