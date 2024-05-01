#!/usr/bin/python3
#
# Maximilian Wilhelm <max@sdn.clinic>
#  --  Mon 18 Mar 2019 07:00:05 PM CET
#
# -*- coding: utf-8 -*-
#
import requests

def ext_pillar(minion_id, pillar, *args, **kwargs):
    data = {
        'nodes': {}
    }

    try:
        nodes = _query(f"http://localhost:5000/salt/get_pillar_info?minion_id={minion_id}")
    except Exception as e:
        raise Exception(f"query NACL: {str(e)}")

    # Store configuration of the minion we asked for in 'node_config' pillar key.
    try:
        pillar['node_config'] = nodes[minion_id]
    except KeyError as e:
        raise Exception(f"No NACL result for minion {minion_id}")

    # Store all node's configuration in 'nodes' pillar key for compatibility

    # If there are no nodes defined in pillar at all, just use ours and be done with it
    if not 'nodes' in pillar:
        data['nodes'] = nodes
        return data

    # IF there are nodes defined in pillar, they take precedence, so only add nodes from
    # NACL which aren't in pillar
    pillar_nodes = pillar.get('nodes', {})
    for node in nodes:
        if node in pillar_nodes:
            continue

        data['nodes'][node] = nodes[node]

    return data


def _query(url):
    res = requests.get(url)
    res.raise_for_status()

    try:
        return res.json()
    except Exception as e:
        raise Exception(f"deserialize JSON: {str (e)}")
