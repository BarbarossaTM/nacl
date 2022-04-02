#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Fri 15 Feb 2019 09:04:27 PM CET
#

import json
import os
import re

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
		'args' : ['GET/minion_id'],
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

	'/ops/ip/add' : {
		'call' : 'add_ip',
		'args' : [ 'POST/status', 'POST/address', 'POST/dns_name?', 'POST/interface?', 'POST/device?', 'POST/vm?' ],
	}
}


# Remove anyting we don't want to share with other minions
def _remove_private_keys (node, node_config):
	# Remove private SSH host keys
	for key_type in ['ecdsa', 'ed25519', 'rsa']:
		try:
			del node_config['ssh']['host'][key_type]['privkey']
		except KeyError:
			continue

	# Remove key of SSL host cert
	try:
		del node_config['certs'][node]['privkey']
	except KeyError:
		pass

	# Remove fastd private keys
	try:
		del node_config['fastd']['intergw_privkey']
		# If intergw_privkey isn't present, nodes_privkey won't either
		del node_config['fastd']['nodes_privkey']
	except KeyError:
		pass

	# Remove Wireguard private keys
	try:
		del node_config['wireguard']['privkey']
	except KeyError:
		pass


def _generate_ibgp_peers (nodes, node_id):
	peers = {
		4: [],
		6: [],
	}

	AFs = []

	our_roles = nodes[node_id].get ('roles', [])
	# If we aren't a router there's nothing to do here
	if not 'router' in our_roles:
		return None

	# Check which AFs we support (for what AFs we have a primary/loopback IP)
	for af in [ 4, 6 ]:
		if af in nodes[node_id]['primary_ips']:
			AFs.append (af)

	# If we don't support any AF, there's nothing to be done here
	if not AFs:
		return None

	for node in sorted (nodes.keys ()):
		if node == node_id:
			continue

		peer_node_config = nodes[node]

		# If this node isn't a router it won't be a peer
		peer_roles = peer_node_config.get ('roles', [])
		if not 'router' in peer_roles:
			continue

		# Carry on if neither we nor the peer are a RR
		if 'routereflector' not in our_roles and 'routereflector' not in peer_roles:
			continue

		# Don't try to set up sessions to VMs/devices which are "planned", "failed", "decomissioning" and "inventory"
		if peer_node_config.get ('status', '') not in [ '', 'active', 'staged', 'offline' ]:
			continue

		for af in AFs:
			# Only generate a session for this AF if the peer has a primary IP for it
			if af not in peer_node_config['primary_ips']:
				continue

			peer_config = {
				# mangle . and - to _ to make bird happy
				'node' : re.sub ('[.-]', '_', node),
				'ip' : peer_node_config['primary_ips'][af].split ('/')[0],
				'rr_client' : False,
			}

			if 'routereflector' in our_roles and not 'routereflector' in peer_roles:
				peer_config['rr_client'] = True

			peers[af].append (peer_config)

	return peers


class Nacl (object):
	def __init__ (self, config_file):
		self.endpoints = endpoints

		self._read_config (config_file)

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


	def get_pillar_info (self, minion_id):
		nodes = self.netbox.get_nodes ()

		# Filter out any private keys which are not for <minion_id>
		for node, node_config in nodes.items ():
			if node != minion_id:
				_remove_private_keys (node, node_config)

			# Remove burp specific config if this node_config isn't for <minion_id>
			# nor <burp_server>
			if "burp" in node_config:
				if node != minion_id and minion_id not in self.config['services']['burp']['servers']:
					del node_config['burp']

			# Remove any subdicts from node_config if _nacl_visibility_ is present,
			# set to 'node' and this node_config is not for <minion_id>
			keys_to_delete = []
			for key, item in node_config.items ():
				if type (item) == dict and '_nacl_visibility_' in item:
					nv = item['_nacl_visibility_']

					# If this subsection should only be visibly for the corresponding node
					# which is different to <minion_id>, mark this subsection to be removed.
					if nv == "node" and node != minion_id:
						keys_to_delete.append (key)

					del node_config[key]['_nacl_visibility_']

			for key in keys_to_delete:
				del node_config[key]

		if minion_id in nodes:
			nodes[minion_id]['routing'] = {
				'bgp' : {
					'internal' : {
						'peers' : _generate_ibgp_peers (nodes, minion_id),
					},
				},
			}

		return nodes


	def add_surge_protector (self, name, site):
		return self.netbox.add_surge_protector (name, site)


	def add_patchpanel (self, name, site, ports):
		return self.netbox.add_patchpanel (name, site, ports)


	def connect_panel_to_surge (self, panel_name, panel_port, surge_name):
		return self.netbox.connect_panel_to_surge (panel_name, panel_port, surge_name)

	def add_ip (self, status, address, dns_name = None, interface = None, device = None, vm = None):
		if_id = None
		if interface:
			if_id = self.netbox.get_interface (interface, device_name = device, vm_name = vm)
			if not if_id:
				raise NaclError ("Did not find interface, not adding IP address!")

		return self.netbox.add_ip (status, address, dns_name, if_id)
