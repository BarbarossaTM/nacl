#!/usr/bin/python3
#
# Maximilian Wilhelm <max@sdn.clinic>
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

	nodes = _query ("http://localhost:5000/salt/get_pillar_info?minion_id=%s" % minion_id)

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
