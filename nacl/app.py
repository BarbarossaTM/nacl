#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Fri 15 Feb 2019 09:04:27 PM CET
#
import json

from nacl.common import *
from nacl.errors import NaclError
import nacl.cache
import nacl.modules
import nacl.netbox


endpoints = {
	# API endpoints called by nodes
	'/node/register_ssh_key' : {
		'call' : 'register_ssh_key',
		'args' : ['request/remote_addr', 'POST/key_type', 'POST/key', 'POST/mac?'],
	},

	'/node/whoami' : {
		'call' : 'whoami',
		'args' : ['request/remote_addr', 'GET/mac?'],
	},


	# API endpoints called by Salt
	'/salt/get_pillar_info' : {
		'call' : 'get_pillar_info',
		'args' : ['GET/minion_id'],
	},
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


def _expand_roles(node_config, role_map):
	roles = node_config.get('roles', [])

	node_role = node_config.get('role')
	if node_role:
		for role in role_map.get(node_role, []):
			if role not in roles:
				roles.append(role)

	node_config['roles'] = sorted(roles)


def _get_allowed_down_OSPF_interfaces(nodes, node_name, infra_domain):
	node_config = nodes[node_name]

	ifaces_down_OK = []

	for ifname in sorted (node_config['ifaces'].keys()):
		iface_config = node_config['ifaces'][ifname]

		# Interface marked as planned/offline in NetBox?
		if iface_config.get ('status', '') in [ 'planned', 'offline' ]:
			ifaces_down_OK.append (ifname)
			continue

		# Wireguard tunnel?
		if ifname.startswith ("wg-"):
			peer = "%s.%s" % (ifname[3:], infra_domain)
			peer_config = nodes.get(peer)
			if not peer_config:
				continue

			if peer_config.get ('status', '') != 'active':
				ifaces_down_OK.append (ifname)

	return ifaces_down_OK


def _read_config (config_file):
	try:
		with open (config_file, 'r') as config_fh:
			return json.load (config_fh)
	except IOError as i:
		raise NaclError ("Failed to read config from '%s': %s" % (config_file, str (i)))


class Nacl (object):
	def __init__ (self, config_file, logger, enable_cache):
		self.log = logger
		self.endpoints = endpoints

		self.config = _read_config(config_file)

		self.module_manager = nacl.modules.ModuleManager(self.config, logger)

		self.netbox = nacl.netbox.Netbox (self.config['netbox'], self.config.get ('defaults', {}))

		if enable_cache:
			self.netbox_cache = nacl.cache.NaclCacheObject ("NetBox", logger, self.netbox.get_nodes, 60)
			self.get_nodes_func = self.netbox_cache.get_data
		else:
			self.get_nodes_func = self.netbox.get_nodes


	def get_endpoints (self):
		return self.endpoints

	#
	# Endpoints
	#

	# Register given ssh key of given type for device with given IP if none is already present
	def register_ssh_key (self, remote_addr, key_type, key, mac = None):
		node = None

		if mac is not None:
			node = self.netbox.get_node_by_mac (mac)
		else:
			node = self.netbox.get_node_by_ip (remote_addr)

		if not node:
			raise NaclError (f"No node found for IP {remote_addr} / MAC {mac}!")

		ext_key = self.netbox.get_node_ssh_key (node, key_type)
		if ext_key:
			if key.strip() == ext_key:
				return NaclResponse ("Key already set", code = 200)

			raise NaclError (f"Key of type '{key_type}' already present for node '{node['name']}'!")

		self.netbox.set_node_ssh_key (node, key_type, key)
		return NaclResponse ("Key registered", code = 201)


	# Return the FQDN of the node identified by the remote IP or given MAC address, if we know it
	def whoami (self, remote_addr, mac = None):
		node = None

		if mac is not None:
			node = self.netbox.get_node_by_mac (mac)
		else:
			node = self.netbox.get_node_by_ip (remote_addr)

		if node is None:
			raise NaclError (f"No node found for IP {remote_addr} / MAC {mac}!")

		return NaclResponse (node['name'])


	def get_pillar_info (self, minion_id):
		nodes = self.get_nodes_func ()

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

		# Map NetBox device role to internal roles
		for node_config in nodes.values():
			_expand_roles(node_config, self.config.get("role_map", {}))


		if minion_id in nodes:
			generated_config = {
				'routing' : {
					'ospf' : {
						'ifaces_down_ok' : _get_allowed_down_OSPF_interfaces(nodes, minion_id, self.config.get ('DNS', {}).get ('infra_domain')),
					},
				},
			}

			nodes[minion_id].update (generated_config)

		# Run any configured modules to derive and generate dynamic bits of the configuration.
		self.module_manager.run_modules(nodes, minion_id)

		return NaclResponse (nodes)
