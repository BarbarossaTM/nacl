#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Mon 18 Mar 2019 07:00:05 PM CET
#
# -*- coding: utf-8 -*-
#

import json
import requests


def ext_pillar (minion_id, pillar, *args, **kwargs):
	data = {
		'nodes' : {}
	}

	nodes = _query ("http://localhost:5000/salt/get_pillar_info")

	# Filter out and private keys which are not for <minion_id>
	for node, node_config in nodes.items ():
		if node != minion_id:
			_remove_private_keys (node, node_config)

	# If there are no nodes defined in pillar at all, just use ours and be done with it
	if not 'nodes' in pillar:
		data['nodes'] = nodes
		return data

	# IF there are nodes defined in pillar, they take precedence, so only add nodes from
	# NACL which aren't in pillar
	pillar_nodes = pillar.get ('nodes', {})
	for node in nodes:
		if node in pillar_nodes:
			continue

		data['nodes'][node] = nodes[node]

	return data


def _query (url):
	res = requests.get (url)
	if res.status_code != 200:
		raise Exception ("Got a %s from NACL: %s" % (res.status_code, res.text))

	try:
		return res.json ()
	except Exception as e:
		raise Exception ("Failed to deserialize NACL data: %s" % str (e))


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
