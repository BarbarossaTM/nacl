#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Fri 15 Feb 2019 09:04:27 PM CET
#

import json
import os
import redis

from nacl.errors import *
import nacl.netbox


endpoints = {
	# API endpoints called by nodes
	'/node/register_ssh_key' : {
		'call' : 'register_ssh_key',
		'args' : ['request/remote_addr', 'POST/key_type', 'POST/key'],
	},


	# API endpoints called by Salt
	'/salt/get_pillar_info' : {
		'call' : 'get_pillar_info',
	},


	# API endpoints called by CLI tools / ops
	'/ops/devices/add_surge_protector' : {
		'call' : 'add_surge_protector',
		'args' : ['POST/name', 'POST/site'],
	},

	'/ops/devices/add_patchpanel' : {
		'call' : 'add_patchpanel',
		'args' : ['POST/name', 'POST/site', 'POST/ports'],
	},

	'/ops/cables/connect_panel_to_surge' : {
		'call' : 'connect_panel_to_surge',
		'args' : [ 'POST/panel_name', 'POST/panel_port', 'POST/surge_name'],
	},
}


class Nacl (object):
	def __init__ (self, config_file):
		self.endpoints = endpoints

		self._read_config (config_file)

		self.redis = redis.Redis (self.config['redis_host'], self.config['redis_port'])
		self.netbox = nacl.netbox.Netbox (self.config['netbox'], self.config.get ('blueprints', {}), self.config.get ('defaults', {}))


	def _read_config (self, config_file):
		try:
			with open (config_file, 'r') as config_fh:
				self.config = json.load (config_fh)
		except IOError as i:
			raise NaclError ("Failed to read config from '%s': %s" % (config_file, str (i)))


	def get_endpoints (self):
		return self.endpoints

	#
	# Endpoints
	#

	# Register given ssh key of given type for device with given IP if none is already present
	def register_ssh_key (self, remote_addr, key_type, key):
		node = self.netbox.get_node_by_ip (remote_addr)
		if not node:
			raise NaclError ("No node found for IP '%s'." % remote_addr)

		if self.netbox.get_node_ssh_key (node[0], node[1], key_type):
			raise NaclError ("Key of type '%s' already present for node '%s'!" % (key_type, remote_addr))

		return self.netbox.set_node_ssh_key (node[0], node[1], key_type, key)


	def get_pillar_info (self):
		return self.netbox.get_nodes ()


	def add_surge_protector (self, name, site):
		return self.netbox.add_surge_protector (name, site)


	def add_patchpanel (self, name, site, ports):
		return self.netbox.add_patchpanel (name, site, ports)


	def connect_panel_to_surge (self, panel_name, panel_port, surge_name):
		return self.netbox.connect_panel_to_surge (panel_name, panel_port, surge_name)
