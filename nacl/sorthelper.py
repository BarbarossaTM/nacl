#!/usr/bin/python3
#
# Maximilian Wilhelm <max@sdn.clinic>
#  -- Fri, 05 Apr 2024 22:09:13 +0200
#
from functools import cmp_to_key
import re

VLAN_VXLAN_IFACE_ER = re.compile (r'^vlan(\d+)|^vx_v(\d+)_(\w+)')

def get_interface_list_from_dict_keys(ifaces: dict):
    """Return the sorted list of keys of the given interfaces dict."""
    return sorted(ifaces.keys(), key = cmp_to_key(_iface_sort))

def sort_interface_list(ifaces: list[str]):
    """Return the sorted list of interfaces."""
    return sorted(ifaces, key = cmp_to_key(_iface_sort))


################################################################################
#                                  Internal helpers                            #
################################################################################

def _cmp(x, y):
    """Most generic comparator."""
    if x < y:
        return -1
    elif x == y:
        return 0
    else:
        return 1

def _iface_sort(iface_a, iface_b):
    a = VLAN_VXLAN_IFACE_ER.search(iface_a)
    b = VLAN_VXLAN_IFACE_ER.search(iface_b)

    # At least one interface didn't match, do regular comparison
    if not a or not b:
        return _cmp(iface_a, iface_b)

    # Extract VLAN ID from VLAN interface (if given) or VXLAN
    vid_a = a.group(1) if a.group(1) else a.group(2)
    vid_b = b.group(1) if b.group(1) else b.group(2)

    # If it's different type of interfaces (one VLAN, one VXLAN), do regular comparison
    if (a.group(1) == None) != (b.group(1) == None):
        return _cmp(iface_a, iface_b)

    # Ok, t's two VLAN or two VXLAN interfaces

    # If it's VXLAN interfaces and the VLAN ID is the same, sort by site name
    if a.group(2) and vid_a == vid_b:
        return _cmp(a.groups(2), b.groups(2))

    # If it's two VLANs or two VXLANs with different VLAN IDs, sort by VLAN ID
    else:
        return _cmp (int(vid_a), int(vid_b))
