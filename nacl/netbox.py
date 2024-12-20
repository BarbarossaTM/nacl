#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sun 22 Apr 2018 11:10:55 AM CEST
#

import copy
import ipaddress
import re
import requests

from nacl.errors import *
import nacl.netboxhelpers as nbh

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
interface_attrs = ['mac_address', 'mtu', 'tagged_vlans', 'untagged_vlan', 'description']
# ... and their names for us
interface_attr_map = {
	'mac_address' : 'mac',
	'description' : 'desc',
}

#
# Regular expression to match tag information
#

# batman_connect_<site>
batman_connect_re = re.compile (r'^batman_connect_(.*)$')
# batman_iface_<site>
batman_iface_re = re.compile (r'^batman_iface_(.*)$')
# mesh_breakout_<site>
mesh_breakout_re = re.compile (r'^mesh_breakout_(.*)$')
# ospf_cost_<cost>
ospf_cost_re = re.compile (r'^ospf_cost_([0-9]+)$')

################################################################################
#                                  Helpers                                     #
################################################################################

def get_parent_iface (iface_config):
	# "parent": null,
	if not iface_config['parent']:
		return None

	# "parent": {
	#	"id": 322,
	#	"name": "bond0",
	#	"device" : { ... },
	#	"name": "bond0"
	#	...
	# }
	return iface_config['parent']['name']


def gen_vm_host_config_for_iface (ifname, iface_cfg, raw_config):
	# If this iface has a parent it isn't exposed to the host
	if get_parent_iface (raw_config):
		return False

	if ifname in ['lo'] or iface_cfg.get ('link-type') == 'dummy':
		return False

	for prefix in ['br-', 'gre_', 'ovpn-', 'wg-']:
		if ifname.startswith (prefix):
			return False

	# If we are still here, there's a good chance this iface is exposed to the VM host
	return True

def get_platform(node_config):
	if node_config['platform'] is None:
		return None

	return node_config['platform']['slug']


# Group a list of ports (integers) into ranges
def _group_ports (port_list):
	ranges = []
	numbers = sorted (map (int, port_list))
	prev = min (port_list)

	for n in numbers:
		if n == prev + 1:
			ranges[-1].append (n)
		else:
			ranges.append ([n])

		prev = n

	return ["%d-%d" % (r[0], r[-1]) if len (r) > 1 else str (r[0]) for r in ranges]


class Netbox (object):
	def __init__ (self, config, defaults):
		self._headers = {
			'Accept': 'application/json',
			'Authorization' : "Token %s" % config['auth_token'],
		}

		self.base_url = config['url'].strip ('/') + "/api/"
		self.defaults = defaults

		self.cache = {
			'sites' : {}
		}

		self._get_sites ()


	def _query (self, url, single_value = False, **kwargs):
		req = requests.get (self.base_url + url, headers = self._headers, **kwargs)
		if req.status_code != 200:
			return None

		res = req.json ()

		if single_value:
			return res

		data = res['results']

		# Check if we reached the server's response limit, if so we need to do
		# additional query/ies to fetch all data.
		while res['next'] is not None:
			req = requests.get (res['next'], headers = self._headers, **kwargs)
			if req.status_code != 200:
				return None

			res = req.json ()
			data.extend(res['results'])

		return data


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


	def _is_valid_ssh_key_type (self, key_type):
		return key_type in valid_ssh_key_types

	def _validate_ssh_key_type (self, key_type):
		if not self._is_valid_ssh_key_type (key_type):
			raise NetboxError ("Invalid ssh_key_type '%s'" % key_type)

	def _validate_device_type (self, device_type):
		if device_type not in path_map:
			raise NetboxError ("Invalid device_type %s" % device_type)


	#
	# Config context / SSH
	#
	def get_node_ssh_key (self, node, key_type):
		self._validate_ssh_key_type (key_type)

		try:
			key = node['config_context']['ssh'][key_type]

			# Just return the public key (without trailing space)
			if key_type.endswith (".pub"):
				return key.strip ()

			return self._unfuck_crypto_key (key)
		except KeyError:
			return None


	def _unfuck_crypto_key (self, key):
		# Fix line breaks in crypto keys
		fixed_key = ""
		for word in key.split ():
			fixed_key += word

			# Linebreak after marker and key parts
			if word.endswith ("---") or len (word) > 23 or '=' in word:
				fixed_key += "\n"
			# Spaces after parts of marker
			elif len (word) < 23:
				fixed_key += " "

		return fixed_key.strip ()


	# Return all know key types (if present)
	def get_node_ssh_keys (self, node):
		keys = {}

		for key_type in valid_ssh_key_types:
			keys[key_type] = self.get_node_ssh_key (node, key_type)

		return keys


	def set_node_ssh_key (self, node, key_type, key):
		self._validate_ssh_key_type (key_type)

		data = {
			'name' : node['name'],
			'local_context_data' : node['config_context'],
		}

		data['local_context_data']['ssh'][key_type] = key.replace ("\n", " ")

		# A VMs has to have the cluster set..
		node_type = "device"
		if not 'device_type' in node:
			node_type = "virtual_machine"
			data['cluster'] = node['cluster']['id']

		res = self._patch ("%s/%s/" % (path_map[node_type], node['id']), data)


	#
	# Interfaces / IPs
	#
	def _get_vlan_ids (self, tagged_vlans):
		vlan_ids = []

		for vlan_info in tagged_vlans:
			vlan_ids.append (vlan_info['vid'])

		return sorted (vlan_ids)


	def _update_bonding_config (self, interfaces):
		bonds = {}

		for ifname, iface_config in interfaces.items ():
			lag = iface_config.get ('lag', None)
			if not lag:
				continue

			if lag not in bonds:
				bonds[lag] = []

			bonds[lag].append (ifname)

		for bond in bonds:
			interfaces[bond]['bond-slaves'] = " ".join (sorted (bonds[bond]))

			# On Linux we don't need interface config stazas for bond members
			for member in bonds[bond]:
				interfaces[member]['enabled'] = False


	def _update_bridge_config (self, interfaces):
		bridges = {}

		for ifname, iface_config in interfaces.items ():
			br = iface_config.get ('bridge-member')
			if not br:
				continue

			if br not in bridges:
				bridges[br] = []

			bridges[br].append (ifname)

		for br in bridges:
			# As VM interface don't have a type we may not have added this yet, D'oh
			if not 'bridge-ports' in interfaces[br]:
				interfaces[br]['bridge-ports'] = []

			interfaces[br]['bridge-ports'] = sorted (interfaces[br]['bridge-ports'] + bridges[br])


	# Get primary IPv4 and IPv6 address/plen, if set
	def _get_primary_ips (self, node_config):
		ips = {}

		if node_config['primary_ip4']:
			ips['4'] = node_config['primary_ip4']['address']
			ips['v4'] = node_config['primary_ip4']['address']

		if node_config['primary_ip6']:
			ips['6'] = node_config['primary_ip6']['address']
			ips['v6'] = node_config['primary_ip6']['address']

		return ips


	def get_node_by_ip (self, ip):
		params = {
			'address' : ip,
		}

		try:
			res = self._query ("ipam/ip-addresses/", params = params)
			if not res:
				return None

			if len (res) != 1:
				raise NetboxError (f"Got {len (res)} interfaces with IP {ip}!")

			iface = res[0]['assigned_object']

			# For VMs 'virtual_machine' is a dict, otherwise it's present but None
			vm = iface.get ('virtual_machine', None)
			if vm:
				return self.get_node ('virtual_machine', vm['id'])

			# For devices 'device' is a dict, otherwise it's present but None
			device = iface.get ('device', None)
			if device:
				return self.get_node ('device', device['id'])
		except IndexError:
			return None
		except KeyError:
			return None


	def get_node_by_mac (self, mac):
		params = {
			'mac_address' : mac,
		}

		try:
			res = self._query ("dcim/interfaces/", params = params)
			if not res:
				res = self._query ("virtualization/interfaces/", params = params)

			if not res:
				return None

			if len (res) != 1:
				raise NetboxError (f"Got {len (res)} interfaces with MAC {mac}!")

			iface = res[0]

			# For VMs 'virtual_machine' is a dict, otherwise it's present but None
			vm = iface.get ('virtual_machine', None)
			if vm:
				return self.get_node ('virtual_machine', vm['id'])

			# For devices 'device' is a dict, otherwise it's present but None
			device = iface.get ('device', None)
			if device:
				return self.get_node ('device', device['id'])
		except IndexError:
			return None
		except KeyError:
			return None


	def get_node (self, node_type, node_id):
		self._validate_device_type (node_type)

		node_info = self._query ("%s/%s" % (path_map[node_type], node_id), True)

		if not 'id' in node_info:
			raise NetboxError ("Node of type '%s' and ID '%s' not found." % (node_type, node_id))

		return node_info


	# Return a dict of all nodes (read: devices + VMs)
	def get_nodes (self):
		nodes = self.get_devices ()

		# Merge in VMs
		vms = self.get_vms ()
		for vm in vms:
			if vm in nodes:
				# XXX Is this possible? XXX
				raise NetboxError ("VM %s clashes with device of the same name!" % vm["name"])

			nodes[vm] = vms[vm]

		# If we're still here, all names were unique. Let's merge in IPs then
		self._store_ip_addresses (nodes)

		# Query and store all services
		self._store_services (nodes)

		# Associate VMs with their hosts
		self._associate_vms_to_hosts (nodes)

		return nodes


	def _device_eligible(self, node_config):
		if node_config['device_role']['slug'] == 'core-switch':
			return True

		if get_platform(node_config) == 'linux':
			return True

		return False


	# Return a dict of all devices with interfaces
	def get_devices (self):
		devices = {}

		for device_config in self._query ("dcim/devices/?limit=0"):
			if not self._device_eligible(device_config):
				continue

			name = device_config['name']

			device = {
				'role' : device_config['device_role']['slug'],
				'hardware' : True,
				'manufacturer' : device_config['device_type']['manufacturer']['name'],
				'model' : device_config['device_type']['model'],
				'oob' : {},
			}

			# Merge in attributes common to devices and VMS
			device.update (self._get_common_attributes (device_config))

			devices[name] = device

		# Query all interfaces and store information to devices
		self._get_interfaces (devices, 'device')

		# Pimp interface configs wrt to LAGs and VLANs
		for device, device_config in devices.items ():
			ifaces = device_config.get ('ifaces')
			if ifaces:
				self._update_bonding_config (ifaces)
				self._update_bridge_config (ifaces)

		return devices


	# Return a dict of all VMs with interfaces
	def get_vms (self):
		vms = {}

		for vm_config in self._query ("virtualization/virtual-machines/?limit=0"):
			name = vm_config['name']

			vm = {
				'virtual' : True,
				'role' : vm_config['role']['slug'],
				'cluster' : vm_config['cluster']['name'],
				'vm_config' : {
					'vcpus' : vm_config['vcpus'],
					'memory' : vm_config['memory'],
					'disk' : vm_config['disk'],
				},
			}

			# Merge in attributes common to devices and VMS
			vm.update (self._get_common_attributes (vm_config))

			vms[name] = vm

		self._get_interfaces (vms, 'vm')

		return vms

	# Get common attributes of devices and VMs
	def _get_common_attributes (self, node_config):
		node = {
			'primary_ips' : self._get_primary_ips (node_config),
			'id' : node_config['custom_fields'].get ('id', None),
			'status' : node_config['status']['label'].lower (),
			'location' : self._get_location_info (node_config['site']['slug'], node_config),
			'sysLocation' : node_config['site']['name'],	# XXX DEPRECATED XXX
			#
			# Maybe in config_context:
			# roles, sites, ifaces, monitoring, mailname, ...
		}

		node['platform'] = get_platform(node_config)
		if node['platform'] == "linux":
			node['certs'] = self._get_node_ssl_certs (node_config)
			node['ssh'] = self._get_node_ssh_keys (node_config)

		tags = self._get_tag_slugs (node_config['tags'])

		# Temporary status override?
		if 'offline' in tags:
			node['status'] = 'offline'

		# Store tags for evaluation within Salt
		node['tags'] = tags

		# Process some tags with special meaning
		if 'ifupdown2' in tags:
			node['network'] = {
				'suite' : 'ifupdown2',
			}
		if 'ifupdown-ng' in tags:
			node['network'] = {
				'suite' : 'ifupdown-ng',
			}

		# Merge in config_context data, IFF it doesn't overwrite anything
		for key, value in node_config.get ('config_context', {}).items ():
			# Those need special care
			if key in ['ssh', 'ssl']:
				continue

			node[key] = value

		return node


	# Gather all relevant interface information we need from netbox
	def _get_interfaces (self, nodes, node_type):
		if node_type == 'device':
			ifaces = self._query ("dcim/interfaces/?limit=0")
		else:
			ifaces = self._query ("virtualization/interfaces/?limit=0")

		for iface_config in ifaces:
			# Netbox has two calles for interfaces, one for "devices" (something you can touch)
			# and VMs (something running in the cloud, maybe on prem, maybe not) which both kind
			# of show all interfaces, but not all with all information.. So we have to distinguish
			# as well. D'oh.
			if node_type == "device":
				if not iface_config['device']:
					continue

				node_name = iface_config['device']['name']

			else:
				if not iface_config['virtual_machine']:
					continue

				node_name = iface_config['virtual_machine']['name']

			# If we didn't find the node, we seem to not care about it, so there's no point in caring
			# about this interface either
			node_config = nodes.get (node_name, None)
			if not node_config:
				continue

			# Make sure there is a ifaces dict present within this nodes config
			if 'ifaces' not in node_config:
				node_config['ifaces'] = {}

			# Name of the interface we are dealing with
			ifname = iface_config['name']

			# Store OOB interfaces seperately so we can store an IP address configured on it later
			# when we query all IP addresses. Sadly the ipaddress API call does not return wether
			# an interface the IP is bound to is OOB or not, so we have to work around that *sniff*
			if iface_config.get ('mgmt_only', False):
				node_config['oob'][ifname] = {}
				continue

			# There may be a (partial) ifaces dict present already when set via confix_context.
			# If so, we use it as base
			iface = node_config['ifaces'].get (ifname, {})

			# Store interface enabled flag
			iface['enabled'] = iface_config['enabled']

			if 'prefixes' not in iface:
				iface['prefixes'] = []

			# Translate tags and store them, if present
			iface_config['tags'] = self._get_tag_slugs (iface_config['tags'])
			if iface_config['tags']:
				iface['tags'] = iface_config['tags']

			iface['has_gateway'] = 'gateway_iface' in iface_config['tags']

			# VRF set on interface?
			if iface_config['vrf']:
				iface['vrf'] = iface_config['vrf']['name']

			# Set VRF for interface without IPs
			if 'vrf_external' in iface_config['tags']:
				iface['vrf'] = 'vrf_external'

			# Store interface type, if present, and not virtual
			if_type = None
			if 'type' in iface_config:
				if_type = iface_config['type']['value']
				if if_type != 'virtual':
					iface['type'] = if_type


			# Is this a bridge?
			if if_type == 'bridge':
				iface['bridge-ports'] = []

			# Is this interface member of a bridge?
			if iface_config.get ('bridge'):
				iface['bridge-member'] = iface_config['bridge']['name']

			# Store VLAN mode (if set)
			if iface_config['mode']:
				iface['vlan-mode'] = iface_config['mode']['value']

			# Dummy interface?
			if 'dummy' in iface_config['tags']:
				iface['link-type'] = 'dummy'

			# If this interface is used for PPPoE, store it as pppoe interface of the node
			if 'pppoe' in iface_config['tags']:
				if 'pppoe' not in node_config:
					node_config['pppoe'] = {}

				node_config['pppoe']['iface'] = ifname

			# ppp interfaces are started by other means for now - FIXME
			if ifname == 'ppp0':
				iface['auto'] = False

			# Interface status
			iface['status'] = 'active'
			if 'planned' in iface_config['tags']:
				iface['status'] = 'planned'
			elif 'offline' in iface_config['tags']:
				iface['status'] = 'offline'

			# Make sure any static gateway has a worse metric than one learned via bird
			if iface['has_gateway']:
				iface['metric'] = 1337

			# Should we do DHCP?
			if 'dhcp' in iface_config['tags']:
				iface['method'] = 'dhcp'

			# Should uRPF be (de)activated explicitly?
			if 'urpf-enable' in iface_config['tags']:
				iface['urpf'] = True
			elif 'urpf-disable' in iface_config['tags']:
				iface['urpf'] = False

			# Is this a Wireguard tunnel?
			if 'wireguard' in iface_config['tags']:
				peer = None

				for cf in ['wg_peer_device', 'wg_peer_vm']:
					if cf in iface_config['custom_fields'] and iface_config['custom_fields'][cf]:
						peer = iface_config['custom_fields'][cf]['name']

					del iface_config['custom_fields'][cf]

				iface['wireguard'] = {
					'peer' : peer,
				}

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
						'cost' : match.group (1)
					}

			# Any VXLAN overlays found?
			if batman_connect_sites:
				iface['batman_connect_sites'] = batman_connect_sites

			# Is this interface part of a LAG?
			if iface_config.get ('lag'):
				iface['lag'] = iface_config['lag']['name']

			# Try to figure out if this iface is an 802.1q vlan interface
			# and - if so - which interface is the vlan-raw-device.
			parent_iface = get_parent_iface (iface_config)
			if parent_iface and (ifname.startswith ('vlan') or '.' in ifname):
				iface['vlan-raw-device'] = parent_iface

			# IF there are any defaults for this interface, apply them
			try:
				defaults = self.defaults['interfaces']['by_name'][ifname]
				for key, value in defaults.items ():
					iface[key] = value
			except KeyError:
				pass

			# Any custom attributes?
			for key, value in iface_config['custom_fields'].items ():
				if value:
					iface[key] = value

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

				elif key == "untagged_vlan":
					iface[our_key] = iface_config[key]['vid']
					continue

				iface[our_key] = iface_config[key]

			if node_type == 'vm':
				# Classify whether we may want to generate config on the VM host for this iface
				iface['vm_host_cfg'] = gen_vm_host_config_for_iface (ifname, iface, iface_config)


	# Query all services from Netbox and store them at the corresponding node
	def _store_services (self, nodes):
		services = self._query ("ipam/services/?limit=0")
		for srv in services:
			if srv['virtual_machine']:
				node_name = srv['virtual_machine']['name']
			else:
				node_name = srv['device']['name']

			node = nodes.get (node_name)
			if not node:
				continue

			if not 'services' in node:
				node['services'] = []

			name = srv['name']
			if srv['description']:
				name += " - " + srv['description']

			node['services'].append ({
				'descr': name,
				'ports': _group_ports (srv['ports']),
				'proto': srv['protocol']['value'],
				'ips' : {
					4: [ip['address'].split ('/')[0] for ip in srv['ipaddresses'] if ip['family'] == 4],
					6: [ip['address'].split ('/')[0] for ip in srv['ipaddresses'] if ip['family'] == 6],
				},
				'acl' : srv['custom_fields'].get ('service_acl'),
				'additional_prefixes' : srv['custom_fields'].get ('service_acl_additional_prefixes'),
			})


	def _associate_vms_to_hosts (self, nodes):
		for vm, vm_config in nodes.items ():
			# We only care for VMs
			if not vm_config.get ('virtual'):
				continue

			# We should have the VM host present as a device
			vm_host = nodes.get (vm_config['cluster'])
			if not vm_host:
				continue

			if not 'vms' in vm_host:
				vm_host['vms'] = {}

			vm_ifaces = {}
			vm_host['vms'][vm] = {
				'ifaces' : vm_ifaces,
			}

			for iface, iface_cfg in vm_config.get('ifaces', {}).items ():
				# Ignore interfaces which have this set to False or where it doesn't exist.
				# The latter could happen if the interface has been defined via config context.
				vm_host_cfg = iface_cfg.get ('vm_host_cfg')
				if vm_host_cfg != None:
					del iface_cfg['vm_host_cfg']
				if not vm_host_cfg:
					continue

				vm_iface = {}
				vm_ifaces[iface] = vm_iface

				for attr in ['mac', 'mtu', 'tagged_vlans', 'vlan-mode', 'untagged_vlan']:
					vm_iface[attr] = iface_cfg.get (attr)


	# Tags are now represented as a list containing dicts, one for each tag.
	# The dict contains the 'name', 'slug', etc.
	# Build a list of all slugs
	def _get_tag_slugs (self, tags):
		slugs = []

		for tag in tags:
			slugs.append (tag['slug'])

		return slugs


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
			name = node_config.get ('name', node_config.get ('name'))
			raise NetboxError ("SSH keys missing in config_context of node '%s'" % name)


	# Get the nodes SSL certificate
	def _get_node_ssl_certs (self, node_config):
		certs = {}

		try:
			node_name = node_config['name']

			for cn, cert_cfg in node_config['config_context']['ssl'].items ():
				key = cn
				if cn == 'host':
					key = node_name

				cert_cfg = copy.deepcopy (cert_cfg)
				if 'key' in cert_cfg:
					del cert_cfg['key']

				try:
					cert_cfg['cert'] = self._unfuck_crypto_key (node_config['config_context']['ssl'][cn]['cert'])
					cert_cfg['privkey'] = self._unfuck_crypto_key (node_config['config_context']['ssl'][cn]['key'])
				except KeyError:
					pass

				certs[key] = cert_cfg
		except Exception as e:
			raise NetboxError ("Failed to gather SSL certs for node '%s': %s" % (node_name, e))

		return certs


	# Get all IPs
	def _store_ip_addresses (self, nodes):
		ips = self._query ("ipam/ip-addresses/?limit=0")

		for ip in ips:
			# If this IP isn't bound to an interface, we don't care about it here
			if not ip['assigned_object']:
				continue

			ifname = ip['assigned_object']['name']

			# We only care for active IPs
			status = ip['status']['value']
			if status != "active":
				continue

			prefix = ip['address']

			# If the given node is not present in our nodes, we don't care about it
			if 'device' in ip['assigned_object']:
				node = ip['assigned_object']['device']['name']
			else:
				node = ip['assigned_object']['virtual_machine']['name']
			if node not in nodes:
				continue

			# If the interface for this IP isn't present, it's probably disabled so we didn't store it
			try:
				iface = nodes[node]['ifaces'][ifname]
			except KeyError:
				# Check if it's an OOB interface, if so, store the IP and carry on
				try:
					nodes[node]['oob'][ifname] = prefix
					continue
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

			# Static gateway set for this IP?
			gateway = ip['custom_fields'].get ('gateway', None)
			if gateway:
				if not 'gateway' in iface:
					iface['gateway'] = []

				iface['gateway'].append (gateway)

			# Shall we calculate a gateway?
			if iface['has_gateway'] and not gateway:
				self._update_default_gateway (iface, prefix)


	# Calculate fallback gateway
	def _update_default_gateway (self, iface_config, new_ip):
		gateways = iface_config.get ('gateway', [])

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


	def _get_sites (self):
		res = self._query("dcim/sites/?limit=0")
		if res is None:
			return

		sites = {}
		for entry in res:
			sites[entry['slug']] = entry

		self.cache['sites'] = sites


	def _get_location_info (self, site_slug, node_config):
		site = self.cache['sites'].get (site_slug)
		if not site:
			return None

		# Every device or VM has a site
		location_info = {
			'site' : {
				'code' : site['name'],
				'desc' : site['description'],
			}
		}

		# Location override present in config context?
		location_override = node_config['config_context'].get ('location_override')
		if location_override:
			if 'latitude' in location_override and 'longitude' in location_override:
				location_info['latitude'] = location_override['latitude']
				location_info['longitude'] = location_override['longitude']

		# Use site coordinates, if present
		elif site['latitude'] and site['longitude']:
			location_info['latitude'] = site['latitude']
			location_info['longitude'] = site['longitude']

		# Does the site belong to a region?
		# XXX What about nested regions?
		if site['region']:
			location_info['region'] = {
				'code' : site['region']['slug'],
				'name' : site['region']['name']
			}

		return location_info

	def get_prefixes(self):
		ret = []

		res = self._query("ipam/prefixes/?limit=0")
		for nb_pfx in res:
			ret.append(nbh.strip_prefix(nb_pfx))

		return ret
