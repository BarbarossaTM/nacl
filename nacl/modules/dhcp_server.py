#!/usr/bin/python3
#
# Maximilian Wilhelm <max@sdn.clinic>
#  --  Mon 01 Apr 2024 17:55:42 CET
#
import ipaddress
from typing import Optional, Tuple

from nacl.modules import BaseModule
from nacl.sorthelper import sort_interface_list

# Node roles which indicate that a given node is running a DHCP server.
# Used to determine if this module should be run for a given node.
DHCP_SERVER_ROLES = [
    "batman_gw",
    "dhcp-server",
    "edge_router",
    "l3-access",
]

DHCP_PREFIX_ROLES = [
    "l3-access",
    "mgmt",
]

# Prefix attributes to copy over from a prefix queried from NetBox/Nacl
PREFIX_ITEMS = [
    "description",
    "prefix",
    "role",
    "status",
]

PREFIX_ROLE_GATEWAY_PREFIX = "gateway-prefix"

def prefix_is_relevant(pfx: dict, minion_id: str) -> bool:
    if pfx["family"] != 4:
        return False

    # Only render configuration for 'active' and 'deprecated' prefixes
    if pfx["status"] in ["container", "reserved"]:
        return False

    # If the prefix is the sub-prefix from a prefix used within a B.A.T.M.A.N. instance
    # and is assigned to a gateway, it has to have the gateway set and it must be us.
    if pfx.get("role") == PREFIX_ROLE_GATEWAY_PREFIX:
        batman_gw = pfx.get("batman_gateway")
        if batman_gw and batman_gw == minion_id:
            return True

        return False

    if pfx.get("dhcp_enabled"):
        return True

    if pfx.get("role") in DHCP_PREFIX_ROLES:
        return True

    return False

def our_IP_in_prefix(pfx: ipaddress.ip_network, ifaces: dict) -> Optional[Tuple[str,str]]:
    """Check all interface IPs if they are part of the given prefix and return the IP, if so.

    Parameters
    ----------
    pfx: str
        The prefix to check for.
    ifaces: dict
        The interfaces configuration of the given node.

    Returns
    -------
    str, str
        Return the interface and IP (without prefix length) if a match is found.
        If no match is found, None, None is returned.
    """
    for iface, iface_cfg in ifaces.items():
        for ip in iface_cfg.get("prefixes", []):
            ip_obj = ipaddress.ip_network(ip, strict=False)
            if ip_obj.version == 6:
                continue

            if ip_obj.subnet_of(pfx):
                return iface, ip.split("/")[0]

    return None, None

def new_prefix(pfx_obj: ipaddress.ip_network, ip: str, nb_pfx: dict) -> dict:
    new_pfx = {
        "network": pfx_obj.network_address, # Will be stringified after sorting
        "netmask": str(pfx_obj.netmask),
        "routers": ip,
    }

    for item in PREFIX_ITEMS:
        new_pfx[item] = nb_pfx.get(item)

    return new_pfx

def sort_dhcp_prefixes(pfxs: dict) -> list[dict]:
    ret = sorted(pfxs.values(), key=lambda pfx: pfx['network'])

    for pfx in ret:
        pfx["network"] = str(pfx["network"])

    return ret


class Module(BaseModule):
    def should_run(self, node_config) -> bool:
        """Returns whether this module should run for the given node_config.

        Parameters
        ----------
        node_config:
            A node_config dict containing the NACL node configuration generated so far.

        Returns
        -------
        bool:
            Whether the given node is running a DHCP server and hence needs configuration.
        """
        our_roles = node_config.get("roles", [])
        return len(set(DHCP_SERVER_ROLES) & set(our_roles)) > 0

    def run(self, nodes: dict, minion_id: str) -> Optional[dict]:
        """Execute the module for the given node_id.

        Parameters
        ----------
        nodes:
            A dictionary containing all node_configs by their respective minion_id.

        minion_id:
            The Salt minion ID of the minion we should compute the configuraton for.

        Returns
        -------
        dict, optional:
            A dictionary containing the configuration items generated by this module.
            This module will return a dictionary with the `dhcp.server.prefixes` key,
            or None if no configuration has been generated.
        """
        nb_prefixes = self.nacl.get_prefixes()
        potential_prefixes = [pfx for pfx in nb_prefixes if prefix_is_relevant(pfx, minion_id)]
        self.log.debug(f"Found {len(nb_prefixes)} prefixes in NetBox, investigating {len(potential_prefixes)}.")

        dhcp_prefixes = {
            # str(prefix): {
            #   network: ipaddress.ip_network (will be stringified)
            #   netmask: str
            #   routers: str
            #
            # Optional:
            #   ranges: [str]
            # }
        }
        ifaces = set()

        for nb_pfx in potential_prefixes:
            iface = None

            if nb_pfx.get("role") == PREFIX_ROLE_GATEWAY_PREFIX:
                iface, new_pfx = self._handle_batman_prefix(
                    nb_pfx,
                    nodes[minion_id]["ifaces"],
                    minion_id,
                    dhcp_prefixes
                )

            # A "regular" prefix, where the prefix in NetBox is the same as the one configured on the
            # interface of the node.
            else:
               iface, new_pfx = self._handle_regular_prefix(
                   nb_pfx, nodes[minion_id]["ifaces"],
                   minion_id
               )

            if not iface:
                continue

            ifaces.add(iface)
            dhcp_prefixes[str(new_pfx["network"])] = new_pfx

        if not dhcp_prefixes:
            return None

        return {
            "dhcp.server.ifaces": sort_interface_list(list(ifaces)),
            "dhcp.server.prefixes": sort_dhcp_prefixes(dhcp_prefixes),
        }

    def _handle_batman_prefix(self, nb_pfx: dict, ifaces: dict, minion_id: str, dhcp_prefixes: dict) -> Tuple[str, dict]:
        # If this is a B.A.T.M.A.N. gateway prefix, by now we know it's ours, so this node needs to
        # provide DHCP services for it. Each B.A.T.M.A.N. site (L2 domain) has one container prefix
        # assigned in NetBox, which reflect the IP subnet used within the B.A.T.M.A.N. network. For
        # each gateway, a sub-prefix in Netbox reflect the IP block and DHCP range assigned to each
        # gateway. The latter have the DHCP enabled and range configured, so we need to map it back
        # to the supernet, which we can find by checking which IP prefix configured on an interface
        # is the supernet for this prefix. Once we found the supernet we can (and have to) use that
        # as the network to provide DHCP services for.
        # To make matters even more complicated, there are corner cases where multiple sub-prefixes
        # are assigned to the same gateway to have multiple DHCP ranges.
        pfx_obj = ipaddress.ip_network(nb_pfx["prefix"], strict = False)
        pfx_iface = None
        our_ip = None

        for iface, iface_cfg in ifaces.items():
            for ip in iface_cfg.get("prefixes", []):
                ip_obj = ipaddress.ip_network(ip, strict=False)
                if ip_obj.version == 6:
                    continue

                if pfx_obj.subnet_of(ip_obj):
                    pfx_obj = ip_obj
                    pfx_iface = iface
                    our_ip = ip.split("/")[0]
                    break

            if pfx_iface:
                break

        if not pfx_iface:
            self.log.warn(f"No IP found on {minion_id} for B.A.T.M.A.N. prefix {nb_pfx['prefix']}.")
            return None, None

        # We may have multiple sub-prefixes for the real prefix, so we may have already found the
        # real prefix before and should append the DHCP range to it.
        new_pfx = dhcp_prefixes.get(str(pfx_obj.network_address))
        if not new_pfx:
            new_pfx = new_prefix(pfx_obj, our_ip, nb_pfx)
            new_pfx["authoritative"] = False

        # Each B.A.T.M.A.N. prefix SHOULD have a DHCP range set, log a warning if it doesn't.
        range = nb_pfx.get("dhcp_range")
        if not range:
            self.log.warn(f"B.A.T.M.A.N. prefix {nb_pfx['prefix']} does not have a DHCP range set!")
            return pfx_iface, new_pfx

        if not "ranges" in new_pfx:
            new_pfx["ranges"] = []

        new_pfx["ranges"].append(range)

        return pfx_iface, new_pfx

    def _handle_regular_prefix(self, nb_pfx: dict, ifaces: dict, minion_id: str) -> Tuple[str, dict]:
        # Find the local interface and IP related to this prefix. If the local device does not
        # have an interface with an IP from this prefix, it won't be a DHCP server for it.
        pfx_obj = ipaddress.ip_network(nb_pfx["prefix"], strict = False)
        iface, ip = our_IP_in_prefix(pfx_obj, ifaces)
        if not iface:
            return None, None

        new_pfx = new_prefix(pfx_obj, ip, nb_pfx)

        # Usually we will have a range, however there might be prefixes with static leases only.
        range = nb_pfx.get("dhcp_range")
        if range:
            new_pfx["ranges"] = [range]

        return iface, new_pfx