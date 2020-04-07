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
batman_iface_re = re.compile (r'^batman_iface_(.*)$')
mesh_breakout_re = re.compile (r'^mesh_breakout_(.*)$')
ospf_cost_re = re.compile (r'^ospf_cost_([0-9]+)$')

class Netbox (object):
	def __init__ (self, config, blueprints, defaults):
		self._headers = {
			'Accept': 'application/json',
			'Authorization' : "Token %s" % config['auth_token'],
		}

		self.base_url = config['url'].strip ('/') + "/api/"
		self.blueprints = blueprints
		self.defaults = defaults


	def _query (self, url, single_value = False):
		req = requests.get (self.base_url + url, headers = self._headers)
		if req.status_code != 200:
			return None

		res = req.json ()

		if single_value:
			return res

		return res['results']


	def _post (self, url, data):
		res = requests.post (self.base_url + url, headers = self._headers, json = data)
		if res.status_code != 201:
			raise NetboxError ("Call to %s failed with code %s: %s" % (self.base_url + url, res.status_code, res.text))

		return res.json ()


	def _put (self, url, data):
		res = requests.put (self.base_url + url, headers = self._headers, json = data)
		if res.status_code != 200:
			raise NetboxError ("Call to %s failed with code %s: %s" % (self.base_url + url, res.status_code, res.text))

		return res.json ()


	def _patch (self, url, data):
		res = requests.patch (self.base_url + url, headers = self._headers, json = data)
		if res.status_code != 200:
			raise NetboxError ("Call to %s failed with code %s: %s" % (self.base_url + url, res.status_code, res.text))

		return res.json ()


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
		tagged_all_iface = None

		# Gather devices with tagges VLANs and VLAN interfaces
		for ifname, iface_config in interfaces.items ():
			# Interface with explicit tagged VLANs
			tagged_vlans = iface_config.get ('tagged_vlans', None)
			if tagged_vlans:
				raw_devices[ifname] = tagged_vlans

			# Interfacee in Tagged All mode
			if iface_config.get ('vlan_mode') == "Tagged All":
				tagged_all_iface = ifname
				del iface_config['vlan_mode']

			# Vlan interface (identified by name)
			if ifname.startswith ('vlan'):
				# If there's already a vlan-raw-device set, just move on
				if 'vlan-raw-device' in iface_config:
					continue

				# There should only be one interface with Tagged All mode on a Linux box
				vlan_devices[ifname] = iface_config

		# Check if there are corresponding VLAN interface for explicitly configured VLANs
		for raw_device in sorted (raw_devices):
			for vlan in raw_devices[raw_device]:
				ifname = "vlan%s" % vlan

				# If there's no vlan<vid>, there's nuthin' we could do
				if ifname not in vlan_devices:
					continue

				vlan_devices[ifname]['vlan-raw-device'] = raw_device

		# Fall back to Tagged All interface as vlan-raw-device if non has been found yet
		if tagged_all_iface:
			for ifname, iface_config in vlan_devices.items ():
				# If there's already a vlan-raw-device set, just move on
				if 'vlan-raw-device' in iface_config:
					continue

				iface_config['vlan-raw-device'] = tagged_all_iface

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


	# Return a dict of all devices with interfaces
	def get_devices (self):
		devices = {}

		for device_config in self._query ("dcim/devices/?limit=0&platform=linux"):
			name = device_config['display_name']

			device = {
				'roles': self._get_roles (device_config),
				'sites': self._get_sites (device_config),
				'ifaces' : device_config['config_context'].get ('ifaces', {}),
				'certs' : self._get_node_ssl_certs (device_config),
				'ssh' : self._get_node_ssh_keys (device_config),
				'id' : device_config['custom_fields'].get ('id', None),
				'status' : device_config['status']['label'].lower (),
				'location' : self._get_location_info (device_config['site']['id']),
				'sysLocation' : device_config['site']['name'],	# XXX DEPRECATED XXX
			}

			devices[name] = device

		# Query all interfaces and store information to devices
		self._get_interfaces (devices, 'device')

		# Pimp interface configs wrt to LAGs and VLANs
		for device, device_config in devices.items ():
			ifaces = device_config['ifaces']
			if ifaces:
				self._update_bonding_config (ifaces)
				self._update_vlan_config (ifaces)

		return devices


	# Return a dict of all VMs with interfaces
	def get_vms (self):
		vms = {}

		for vm_config in self._query ("virtualization/virtual-machines/?limit=0"):
			name = vm_config['name']

			vm = {
				'roles': self._get_roles (vm_config),
				'sites': self._get_sites (vm_config),
				'ifaces' : vm_config['config_context'].get ('ifaces', {}),
				'certs' : self._get_node_ssl_certs (vm_config),
				'ssh' : self._get_node_ssh_keys (vm_config),
				'id' : vm_config['custom_fields'].get ('id', None),
				'status' : vm_config['status']['label'].lower (),
				'location' : self._get_location_info (vm_config['site']['id']),
				'sysLocation' : vm_config['site']['name'],	# XXX DEPRECATED XXX
			}

			vms[name] = vm

		self._get_interfaces (vms, 'vm')

		# Pimp interface configs wrt VLANs
		for vm, vm_config in vms.items ():
			ifaces = vm_config['ifaces']
			if ifaces:
				self._update_vlan_config (ifaces)

		return vms


	# Gather all relevant interface information we need from netbox information
	def _get_interfaces (self, nodes, node_type):
		if node_type == 'device':
			ifaces = self._query ("dcim/interfaces/?limit=0")
		else:
			ifaces = self._query ("virtualization/interfaces/?limit=0")

		for iface_config in ifaces:
			# Ignore interfaces which are not enabled
			if not iface_config.get ('enabled', False):
				continue

			# Ignore OOB interfaces
			if iface_config.get ('mgmt_only', False):
				continue

			# Netbox has two called for interfaces, one for "devices" (something you can touch)
			# and VMs (something running in the cloud, maybe on prem, maybe not) which both kind
			# of show all interfaces, but not all with all information.. So we have to distinguish
			# as well. D'oh.
			if node_type == "device":
				if not iface_config['device']:
					continue

				node_name = iface_config['device']['display_name']
				node_config = nodes.get (node_name, None)

			else:
				if not iface_config['virtual_machine']:
					continue

				node_name = iface_config['virtual_machine']['name']
				node_config = nodes.get (node_name, None)

			# If we didn't find the node, we seem to not care about it, so there's no point in caring
			# about this interface either
			if not node_config:
				continue

			# There may be a (partial) ifaces dict present already when set via confix_context.
			# If so, we use it as base
			ifname = iface_config['name']
			iface = node_config['ifaces'].get (ifname, {})

			if 'prefixes' not in iface:
				iface['prefixes'] = []

			iface['has_gateway'] = 'gateway_iface' in iface_config['tags']

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

			# Evaluate tags
			batman_connect_sites = []
			for tag in iface_config['tags']:
				# Should we set up VXLAN overlays for B.A.T.M.A.N.?
				match = batman_connect_re.search (tag)
				if match:
					batman_connect_sites.append (match.group (1))

				# Configure interface as B.A.T.M.A.N. mesh interface?
				match = batman_iface_re.search (tag)
				if match:
					iface['type'] = "batman_iface"
					iface['site'] = match.group (1)
					iface['desc'] = "B.A.T.M.A.N. Breakout %s" % match.group (1)

				# Configure interface for mesh breakout?
				match = mesh_breakout_re.search (tag)
				if match:
					iface['type'] = "mesh_breakout"
					iface['site'] = match.group (1)
					iface['desc'] = "Mesh Breakout %s" % match.group (1)

				# Configure OSPF on this interface?
				match = ospf_cost_re.search (tag)
				if match:
					iface['ospf'] = {
						'stub' : False,
						'cost' : match.group (1)
					}

			# Any VXLAN overlays found?
			if batman_connect_sites:
				iface['batman_connect_sites'] = batman_connect_sites

			# Store 802.1Q mode
			if iface_config['mode']:
				iface['vlan_mode'] = iface_config['mode']['label']

			# IF there are any defaults for this interface, apply them
			try:
				defaults = self.defaults['interfaces']['by_name'][ifname]
				for key, value in defaults.items ():
					iface[key] = value
			except KeyError:
				pass

			# Store iface config to device
			node_config['ifaces'][ifname] = iface

			# Store interface attributes we care about
			for key in interface_attrs:
				if not iface_config.get (key, None):
					continue

				our_key = interface_attr_map.get (key, key)

				if key == "tagged_vlans":
					iface[our_key] = self._get_vlan_ids (iface_config[key])
					continue

				iface[our_key] = iface_config[key]


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


	def _get_device_role_id_by_slug (self, slug):
		res = self._query ('dcim/device-roles/?slug=%s' % slug)
		if not res:
			return None

		return res[0]['id']


	def _get_device_type_id (self, manufacterer, slug):
		res = self._query ('dcim/device-types/?manufacterer=%s&slug=%s' % (manufacterer, slug))
		if not res:
			return None

		return res[0]['id']

	def _get_site_id (self, name):
		res = self._query ('dcim/sites/?name=%s' % name)
		if not res:
			return None

		return res[0]['id']


	def _get_location_info (self, site_id):
		site = self._query ("dcim/sites/%s" % site_id, True)
		if not site:
			return None

		location_info = {
			'latitude' : site['latitude'],
			'longitude' : site['longitude'],
			'site' : {
				'code' : site['name'],
				'desc' : site['description'],
			}
		}

		if site['region']:
			location_info['region'] = {
				'code' : site['region']['slug'],
				'name' : site['region']['name']
			}

		return location_info


	def add_surge_protector (self, name, site):
		try:
			blueprint = self.blueprints['surge']
			device_role = self._get_device_role_id_by_slug (blueprint['device_role'])
			device_type = self._get_device_type_id (blueprint['manufacturer'], blueprint['device_type'])
		except KeyError:
			raise BlueprintError ("No or incomplete blueprint configured for 'surge' type!")


		site_id = self._get_site_id (site)
		if not site_id:
			raise NetboxError ("Site '%s' could not be found." % site)

		data = {
			'device_role' : device_role,
			'device_type' : device_type,
			'name' : name,
			'site' : site_id,
			'status' : 1,
		}

		return self._post ("dcim/devices/", data)


	def add_patchpanel (self, name, site, ports):
		try:
			blueprint = self.blueprints['patchpanel']
			device_role = self._get_device_role_id_by_slug (blueprint['device_role'])
			device_type = self._get_device_type_id (blueprint['manufacturer'], blueprint['device_type'])
		except KeyError:
			raise BlueprintError ("No or incomplete blueprint configured for 'patchpanel' type!")

		site_id = self._get_site_id (site)
		if not site_id:
			raise NetboxError ("Site '%s' could not be found." % site)

		# Create device
		data = {
			'device_role' : device_role,
			'device_type' : device_type,
			'name' : name,
			'site' : site_id,
			'status' : 1,
		}

		res = self._post ("dcim/devices/", data)
		if not res:
			raise NetboxError ("Failed to create Patchpanel in Netbox: %s" % res)

		# Create rear ports
		pp_id = res['id']

		for n in range (1, int (ports) + 1):
			data = {
				'device' : pp_id,
				'name' : n,
				'type' : 1000,		# 8P8C
				'positions' : 1,	# 1 Front port per rear port
			}

			try:
				res = self._post ("dcim/rear-ports/", data)
			except NetboxError as e:
				raise NaclError ("Failed to create rear port %s of %s: %s" % (n, name, e))

			data = {
				'device' : pp_id,
				'name' : n,
				'type' : 1000,		# 8P8C
				'rear_port' : res['id'],
				'rear_port_position' : 1,
			}

			try:
				res = self._post ("dcim/front-ports/", data)
			except NetboxError as e:
				raise NaclError ("Failed to create front port %s of %s: %s" % (n, name, e))


	def _get_rear_port_by_name (self, device_name, port_name):
		res = self._query ('dcim/rear-ports/?device=%s&name=%s' % (device_name, port_name))
		if not res:
			return None

		return res[0]['id']


	def connect_panel_to_surge (self, panel_name, panel_port, surge_name, cable_type = None, length = None, status = False):
		termination_a_id = self._get_rear_port_by_name (panel_name, panel_port)
		if not termination_a_id:
			raise NaclError ("Rear port '%s' of panel '%s' doesn't exist!" % (panel_port, panel_name))

		termination_b_id = self._get_rear_port_by_name (surge_name, 1)
		if not termination_b_id:
			raise NaclError ("Rear port '1' of surge protector '%s' doesn't exist!" % surge_name)

		cable = {
			'status' : status,
			'termination_a_type': 'dcim.rearport',
			'termination_a_id' : termination_a_id,
			'termination_b_type': 'dcim.rearport',
			'termination_b_id' : termination_b_id,
		}

		if cable_type:
			cable['type'] = cable_type

		if length:
			if 'cm' in length:
				cable['length_unit'] = 1100	# cm
				cable['length'] = length.replace ('cm', '')
			elif 'm' in length:
				cable['length_unit'] = 1200	# m
				cable['length'] = length.replace ('m', '')

		try:
			res = self._post ("dcim/cables/", cable)
		except NetboxError as e:
			raise NaclError ("Failed to create cable from port '%s' of panel '%s' to surge '%s': %s" % (panel_port, panel_name, surge_name, e))
