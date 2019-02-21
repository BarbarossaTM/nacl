#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sun 22 Apr 2018 11:10:55 AM CEST
#

import json
import requests
import sys


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
interface_attrs = ['mac_address', 'mtu', 'name', 'tagged_vlans', 'untagged_vlan', 'description', 'lag']
# ... and there names for us
interface_attr_map = {
	'mac_address' : 'mac',
	'description' : 'alias',
}

class NetboxError (Exception): {}


class Netbox (object):
	def __init__ (self, config):
		self._headers = {
			'Accept': 'application/json',
			'Authorization' : config['auth_token']
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
		res = req.json ()

		return res


	def _put (self, url, data):
		req = requests.put (self.base_url + url, headers = self._headers, data = data)
		if req.status_code!= 200:
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

			# Just return the public key as is
			if key_type.endswith ("_pub"):
				return key

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

			# Return trailing new line before returning
			return fixed_key.strip ()

		except KeyError:
			return None


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
			interfaces[bond]['bond-salves'] = ",".join (bonds[bond])

			# On Linux we don't need interface config stazas for bond members
			for member in bonds[bond]:
				del interfaces[member]
