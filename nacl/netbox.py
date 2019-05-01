#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sun 22 Apr 2018 11:10:55 AM CEST
#

import ipaddress
import json
import re
import requests
import sys

from nacl.errors import *

path_map = {
	'device' : 'dcim/devices',
	'virtual_machine' : 'virtualization/virtual-machines',
}

valid_ssh_key_types = [
	'ssh_host_ecdsa_key',
	'ssh_host_ecdsa_key.pub',
	'ssh_host_ed25519_key',
	'ssh_host_ed25519_key.pub',
	'ssh_host_rsa_key',
	'ssh_host_rsa_key.pub',
]

# Interface attributes we care about...
interface_attrs = ['mac_address', 'mtu', 'tagged_vlans', 'untagged_vlan', 'description', 'lag']
# ... and there names for us
interface_attr_map = {
	'mac_address' : 'mac',
	'description' : 'desc',
}

# Regular expression to match and split site names from tags
batman_connect_re = re.compile (r'^batman_connect_(.*)$')

class Netbox (object):
	def __init__ (self, config):
		self._headers = {
			'Accept': 'application/json',
			'Authorization' : "Token %s" % config['auth_token'],
		}

		self.base_url = config['url'].strip ('/') + "/api/"


	def _query (self, url, single_value = False):
		req = requests.get (self.base_url + url, headers = self._headers)
		if req.status_code != 200:
			return None

		res = req.json ()

		if single_value:
			return res

		return res['results']


	def _post (self, url, data):
		req = requests.post (self.base_url + url, headers = self._headers, data = data)
		if req.status_code != 200:
			raise NetboxError ("Call to %s failed with code %s" % (base_url + url, req.status_code))

		return req.json ()


	def _put (self, url, data):
		req = requests.put (self.base_url + url, headers = self._headers, data = data)
		if req.status_code != 200:
			raise NetboxError ("Call to %s failed with code %s" % (base_url + url, req.status_code))

		return req.json ()


	def _patch (self, url, data):
		req = requests.patch (self.base_url + url, headers = self._headers, json = data)
		if req.status_code != 200:
			raise NetboxError ("Call to %s failed with code %s" % (base_url + url, req.status_code))

		return req.json ()


	def get_node_by_ip (self, ip):
		try:
			res = self._query ("ipam/ip-addresses/?address=%s" % ip)
			if not res:
				return None

			iface = res[0]['interface']

			# For VMs 'virtual_machine' is a dict, otherwise it's set but None
			vm = iface['virtual_machine']
			if vm:
				return ['virtual_machine', vm['id']]

			# For devices 'device' is a dict, otherwise it's set but None
			device = iface['device']
			if device:
				return ['device', device['id']]
		except IndexError:
			return None
		except KeyError:
			return None


	def _is_valid_ssh_key_type (self, key_type):
		return key_type in valid_ssh_key_types

	def _validate_ssh_key_type (self, key_type):
		if not self._is_valid_ssh_key_type (key_type):
			raise NetboxError ("Invalid ssh_key_type '%s'" % key_type)

	def _validate_device_type (self, device_type):
		if device_type not in path_map:
			raise NetboxError ("Invalid device_type '%s'" % device_id)


	def _get_node_info (self, device_type, device_id):
		self._validate_device_type (device_type)

		node_info = self._query ("%s/%s" % (path_map[device_type], device_id), True)

		if not 'id' in node_info:
			raise NetboxError ("Node of type '%s' and ID '%s' not found." % (device_type, device_id))

		return node_info

	#
	# Config context / SSH
	#
	def get_config_context (self, device_type, device_id):
		return self._get_node_info (device_type, device_id)['config_context']


	def get_node_ssh_key (self, device_type, device_id, key_type):
		self._validate_ssh_key_type (key_type)

		try:
			node_info = self._get_node_info (device_type, device_id)
			key = node_info['config_context']['ssh'][key_type]

			# Just return the public key (without trailing space)
			if key_type.endswith ("_pub"):
				return key.strip ()

			return self._unfuck_crypto_key (key)
		except KeyError:
			return None


	def _unfuck_crypto_key (self, key):
		# Fix line breaks in private keys
		fixed_key = ""
		for word in key.split ():
			fixed_key += word

			# Linebreak after marker and key parts
			if word.endswith ("---") or len (word) > 23:
				fixed_key += "\n"
			# Spaces after parts of marker
			elif len (word) < 23:
				fixed_key += " "

		return fixed_key.strip ()


	# Return all know key types (if present)
	def get_node_ssh_keys (self, device_type, device_id):
		keys = {}

		for key_type in valid_ssh_key_types:
			keys[key_type] = self.get_node_ssh_key (device_type, device_id, key_type)

		return keys


	def set_node_ssh_key (self, device_type, device_id, key_type, key):
		self._validate_ssh_key_type (key_type)

		node_info = self._get_node_info (device_type, device_id)

		data = {
			'name' : node_info['name'],
			'local_context_data' : node_info['config_context'],
		}

		data['local_context_data']['ssh'][key_type] = key.replace ("\n", " ")

		# A VMs has to have the cluster set..
		if device_type == "virtual_machine":
			data['cluster'] = node_info['cluster']['id']

		res = self._patch ("%s/%s/" % (path_map[device_type], device_id), data)


	#
	# Interfaces / IPs
	#
	def _get_vlan_ids (self, tagged_vlans):
		vlan_ids = []

		for vlan_info in tagged_vlans:
			vlan_ids.append (vlan_info['vid'])

		return vlan_ids


	def get_node_interfaces (self, device_type, device_id):
		self._validate_device_type (device_type)

		if device_type == "device":
			res = self._query ("dcim/interfaces/?device_id=%s" % device_id)
		elif device_type == "virtual_machine":
			res = self._query ("virtualization/interfaces/?device_id=%s" % device_id)

		ifaces =  {}

		for iface_config in res:
			ifname = iface_config['name']

			# Ignore interfaces which are not enabled
			if not iface_config.get ('enabled', False):
				continue

			ifaces[ifname] = {}
			iface = ifaces[ifname]

			for key in interface_attrs:
				if not iface_config[key]:
					continue

				our_key = interface_attr_map.get (key, key)

				if key == "tagged_vlans":
					iface[our_key] = self._get_vlan_ids (iface_config[key])
					continue

				iface[our_key] = iface_config[key]

		self._update_bonding_config (ifaces)
		self._update_vlan_config (ifaces)

		return ifaces


	def get_node_interfaces_and_ips (self, device_type, device_id):
		self._validate_device_type (device_type)

		res = self._query ("ipam/ip-addresses/?%s_id=%s" % (device_type, device_id))

		ifaces = self.get_node_interfaces (device_type, device_id)

		for addr_info in res:
			ifname = addr_info['interface']['name']

			# Iface has to be present already
			iface = ifaces[ifname]

			# Prefixes list already there?
			if not 'prefixes' in iface:
				iface['prefixes'] = []

			iface['prefixes'].append (addr_info['address'])

			# Does this IP belong to a VRF?
			if addr_info['vrf']:
				iface['vrf'] = addr_info['vrf']

		return ifaces

	def _update_bonding_config (self, interfaces):
		bonds = {}

		for ifname, iface_config in interfaces.items ():
			lag_config = iface_config.get ('lag', None)
			if not lag_config:
				continue

			lag = lag_config['name']
			if lag not in bonds:
				bonds[lag] = []

			bonds[lag].append (ifname)

		for bond in bonds:
			interfaces[bond]['bond-slaves'] = " ".join (sorted (bonds[bond]))

			# On Linux we don't need interface config stazas for bond members
			for member in bonds[bond]:
				del interfaces[member]


	def _update_vlan_config (self, interfaces):
		raw_devices = {}
		vlan_devices = {}

		# Gather devices with tagges VLANs and VLAN interfaces
		for ifname, iface_config in interfaces.items ():
			tagged_vlans = iface_config.get ('tagged_vlans', None)
			if tagged_vlans:
				raw_devices[ifname] = tagged_vlans

			if ifname.startswith ('vlan'):
				# If there's already a vlan-raw-device set, just move on
				if 'vlan-raw-device' in iface_config:
					continue

				vlan_devices[ifname] = iface_config

		for raw_device in sorted (raw_devices):
			for vlan in raw_devices[raw_device]:
				ifname = "vlan%s" % vlan

				# If there's no vlan<vid>, there's nuthin' we could do
				if ifname not in vlan_devices:
					continue

				vlan_devices[ifname]['vlan-raw-device'] = raw_device


	# Return a dict of all nodes (read: devices + VMs)
	def get_nodes (self):
		nodes = self.get_devices ()

		# Merge in VMs
		vms = self.get_vms ()
		for vm in vms:
			if vm in nodes:
				# XXX Is this possible? XXX
				raise NetboxError ("VM '%s' clashes with device of the same name!" % name)

			nodes[vm] = vms[vm]

		# If we're still here, all names were unique. Let's merge in IPs then
		self._store_ip_addresses (nodes)

		return nodes


	# Return node information for device with given ID
	def get_device (self, device_id):
		device_config = self._query ("dcim/devices/%d"% device_id, True)

		device = {
			'sysLocation' : device_config['site']['name'],
			'roles': self._get_roles (device_config),
			'sites': self._get_sites (device_config),
			'ifaces' : {},
			'certs' : self._get_node_ssl_certs (device_config),
			'ssh' : self._get_node_ssh_keys (device_config),
			'id' : device_config['custom_fields'].get ('id', None),
			'status' : device_config['status']['label'].lower (),
		}

		return device


	# Return a dict of all devices with interfaces
	def get_devices (self):
		devices = {}

		for device_config in self._query ("dcim/devices/?limit=0"):
			role = device_config['device_role']['slug']
			if role in ['switch', 'wbbl']:
				continue

			name = device_config['display_name']

			device = self.get_device (device_config['id'])
			devices[name] = device

		# Query all interfaces and store information to devices
		device_ifaces = self._query ("dcim/interfaces/?limit=0")
		for iface_config in device_ifaces:
			# Ignore interfaces which are not enabled
			if not iface_config.get ('enabled', False):
				continue

			# Interfaces of VMs are returned but without their association :-(
			if not iface_config['device']:
				continue

			# Ignore OOB interfaces
			if iface_config['mgmt_only']:
				continue

			device_name = iface_config['device']['display_name']
			device_config = devices.get (device_name, None)
			if not device_config:
				continue

			ifname = iface_config['name']
			iface = {
				'prefixes' : [],
				'has_gateway' : 'gateway_iface' in iface_config['tags'],
			}

			# Interface status
			iface['status'] = 'active'
			if 'planned' in iface_config['tags']:
				iface['status'] = 'planned'

			# Make sure any static gateway has a worse metric than one learned via bird
			if iface['has_gateway']:
				iface['metric'] = 1337

			# Should we do DHCP?
			if 'dhcp' in iface_config['tags']:
				iface['method'] = 'dhcp'

			# Should we set up VXLAN overlays for B.A.T.M.A.N.?
			batman_connect_sites = []
			for tag in iface_config['tags']:
				match = batman_connect_re.search (tag)
				if match:
					batman_connect_sites.append (match.group (1))

			if batman_connect_sites:
				iface['batman_connect_sites'] = batman_connect_sites

			# Store iface config to device
			device_config['ifaces'][ifname] = iface

			# Store interface attributes we care about
			for key in interface_attrs:
				if not iface_config.get (key, None):
					continue

				our_key = interface_attr_map.get (key, key)

				if key == "tagged_vlans":
					iface[our_key] = self._get_vlan_ids (iface_config[key])
					continue

				iface[our_key] = iface_config[key]

		# Pimp interface configs wrt to LAGs and VLANs
		for device, device_config in devices.items ():
			ifaces = device_config['ifaces']
			if ifaces:
				self._update_bonding_config (ifaces)
				self._update_vlan_config (ifaces)

		return devices


	# Return node information for VM with given ID
	def get_vm (self, vm_id):
		vm_config = self._query ("virtualization/virtual-machines/%d"% vm_id, True)

		vm = {
			'sysLocation' : vm_config['site']['name'],
			'roles': self._get_roles (vm_config),
			'sites': self._get_sites (vm_config),
			'ifaces' : {},
			'certs' : self._get_node_ssl_certs (vm_config),
			'ssh' : self._get_node_ssh_keys (vm_config),
			'id' : vm_config['custom_fields'].get ('id', None),
			'status' : vm_config['status']['label'].lower (),
		}

		return vm


	# Return a dict of all VMs with interfaces
	def get_vms (self):
		vms = {}

		for vm_config in self._query ("virtualization/virtual-machines/?limit=0"):
			name = vm_config['name']

			vm = self.get_vm (vm_config['id'])
			vms[name] = vm

		vm_ifaces = self._query ("virtualization/interfaces/?limit=0")
		for iface_config in vm_ifaces:
			# Ignore interfaces which are not enabled
			if not iface_config.get ('enabled', False):
				continue

			# Interfaces of VMs are returned but without their association :-(
			if not iface_config['virtual_machine']:
				continue

			vm_name = iface_config['virtual_machine']['name']
			vm_config = vms.get (vm_name, None)
			if not vm_config:
				continue

			ifname = iface_config['name']
			iface = {
				'prefixes' : [],
				'has_gateway' : 'gateway_iface' in iface_config['tags'],
			}

			# Interface status
			iface['status'] = 'active'
			if 'planned' in iface_config['tags']:
				iface['status'] = 'planned'

			# Should we do DHCP?
			if 'dhcp' in iface_config['tags']:
				iface['method'] = 'dhcp'

			# Make sure any static gateway has a worse metric than one learned via bird
			if iface['has_gateway']:
				iface['metric'] = 1337

			# Should we set up VXLAN overlays for B.A.T.M.A.N.?
			batman_connect_sites = []
			for tag in iface_config['tags']:
				match = batman_connect_re.search (tag)
				if match:
					batman_connect_sites.append (match.group (1))

			if batman_connect_sites:
				iface['batman_connect_sites'] = batman_connect_sites

			# Store iface config to device
			vm_config['ifaces'][ifname] = iface

			# Store interface attributes we care about
			for key in interface_attrs:
				if not iface_config.get (key, None):
					continue

				our_key = interface_attr_map.get (key, key)

				if key == "tagged_vlans":
					iface[our_key] = self._get_vlan_ids (iface_config[key])
					continue

				iface[our_key] = iface_config[key]

		# Pimp interface configs wrt VLANs
		for vm, vm_config in vms.items ():
			ifaces = vm_config['ifaces']
			if ifaces:
				self._update_vlan_config (ifaces)

		return vms


	# Get the list of roles a node has configured, if any
	def _get_roles (self, node_config):
		return node_config['config_context'].get ('roles', [])


	# Get the list of B.A.T.M.A.N. a node has configured, if any
	def _get_sites (self, node_config):
		return node_config['config_context'].get ('sites', [])


	# Get the nodes SSH hosts keys
	def _get_node_ssh_keys (self, node_config):
		try:
			return {
				'host' : {
					'ecdsa' : {
						'privkey': self._unfuck_crypto_key (node_config['config_context']['ssh']['ssh_host_ecdsa_key']),
						'pubkey': node_config['config_context']['ssh']['ssh_host_ecdsa_key.pub'].strip (),
					},

					'ed25519' : {
						'privkey': self._unfuck_crypto_key (node_config['config_context']['ssh']['ssh_host_ed25519_key']),
						'pubkey': node_config['config_context']['ssh']['ssh_host_ed25519_key.pub'].strip (),
					},

					'rsa' : {
						'privkey': self._unfuck_crypto_key (node_config['config_context']['ssh']['ssh_host_rsa_key']),
						'pubkey': node_config['config_context']['ssh']['ssh_host_rsa_key.pub'].strip (),
					},
				},
			}
		except Exception:
			name = node_config.get ('display_name', node_config.get ('name'))
			raise NetboxError ("SSH keys missing in config_context of node '%s'" % name)


	# Get the nodes SSL certificate
	def _get_node_ssl_certs (self, node_config):
		node_name = node_config.get ('display_name', node_config.get ('name'))
		certs = {}

		try:
			for cn, cert in node_config['config_context']['ssl'].items ():
				key = cn
				if cn == 'host':
					key = node_name

				certs[key] = {
					'cert': self._unfuck_crypto_key (node_config['config_context']['ssl'][cn]['cert']),
					'privkey': self._unfuck_crypto_key (node_config['config_context']['ssl'][cn]['key']),
				}
		except KeyError:
			return {}
		except Exception as e:
			raise NetboxError ("Failed to gather SSL certs for node '%s': %s" % (node_name, e))

		return certs


	# Get all IPs
	def _store_ip_addresses (self, nodes):
		ips = self._query ("ipam/ip-addresses/?limit=0")

		for ip in ips:
			ip_iface = ip['interface']
			# If this IP isn't bound to an interface, we don't care about it here
			if not ip_iface:
				continue
			ifname = ip_iface['name']

			# We only care for active IPs
			status = ip['status']['label']
			if status != "Active":
				continue

			prefix = ip['address']

			node = None
			if ip_iface['device']:
				node = ip_iface['device']['display_name']
			elif ip_iface['virtual_machine']:
				node = ip_iface['virtual_machine']['name']
			else:
				raise NetboxError ("IP '%s' bound to unknown interface. This should not have happend. Ever. At all.")

			# If the given node is not present in our nodes, we don't care about it
			if node not in nodes:
				continue

			# If the interface for this IP isn't present, it's probably disabled so we didn't store it
			try:
				iface = nodes[node]['ifaces'][ifname]
			except KeyError:
				continue

			# Store IP/mask
			iface['prefixes'].append (prefix)

			# VRF set for this IP?
			if ip['vrf']:
				vrf = ip['vrf']['name']

				vrf_present = iface.get ('vrf', None)
				if vrf_present and vrf_present != vrf:
					raise NetboxError ("VRF mismatch on interface '%s' on '%s': %s vs. %s (from %s)" % (ifname, node, vrf_present, vrf, prefix))

				iface['vrf'] = vrf

			# Do we need a gateway?
			if iface['has_gateway']:
				self._update_default_gateway (iface, prefix)

	def _update_default_gateway (self, iface_config, new_ip):
		# This is gonna be ugly... But awlnx wanted it that way and
		# I don't see any better way either right now. ¯\_(ツ)_/¯

		gateways = iface_config.get ('gateway', [])

		# FIXME Check if there already is a gateway for this protocol? FIXME

		# An ipaddress network object is a nice thing to deal with
		network = ipaddress.ip_network (new_ip, strict = False)
		plen = network.prefixlen

		# If this is a transfer network (/31 or /126 or /127) we use 'the other' IP
		if plen in [ 31, 126, 127 ]:
			index_map = {
				31 : 0,
				126 : 1,
				127 : 0,
			}

			# Extract the first IP of this prefix
			new_gw = ipaddress.ip_address (network[index_map[plen]])
			new_ip_obj = ipaddress.ip_address (new_ip.split ('/')[0])

			# If the first IP is ours, use the other (next) one
			if new_gw == new_ip_obj:
				new_gw = str (network[index_map[plen] + 1])

			gateways.append (new_gw)

		# Ok, not a transfer network but a "real" subnet, let's use the first IP of it
		else:
			gateways.append (str (network[1]))

		iface_config['gateway'] = gateways

