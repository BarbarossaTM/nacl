
#!/usr/bin/python3
#
# Maximilian Wilhelm <max@sdn.clinic>
#  --  Mon 01 Apr 2024 00:02:39 CET
#
from typing import Optional

from nacl.modules import BaseModule, ModuleError

class Module(BaseModule):
    def should_run (self, node_config) -> bool:
        """Returns whether this module should run for the given node_config.

        Parameters
        ----------
        node_config:
            A node_config dict containing the NACL node configuration generated so far.

        Returns
        -------
            bool
        """
        AFs = []

        our_roles = node_config.get("roles", [])
        # If we aren't a router there's nothing to do here
        if "router" not in our_roles:
            return False

        # Check which AFs we support (for what AFs we have a primary/loopback IP)
        for af in [ "4", "6" ]:
            if af in node_config["primary_ips"]:
                AFs.append (af)

        # If we don't support any AF, there's nothing to be done here
        if not AFs:
            return False

        return True

    def run (self, nodes: dict, minion_id: str) -> Optional[dict]:
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
            Items are identified by a hierarchical key with elements separated by dots,
            e.g. routing.bgp.internal.peers or wireguard.
            A return value of None may be used to indicate that no configuration has been generated.
        """
        peers = {
           "4": [],
           "6": [],
        }

        node = nodes[minion_id]

        AFs = []
        # Check which AFs we support (for what AFs we have a primary/loopback IP)
        for af in [ "4", "6" ]:
           if af in node["primary_ips"]:
               AFs.append (af)

        # If we don't support any AF, there's nothing to be done here
        if not AFs:
           raise ModuleError(f"No primary IP found for node {minion_id}!")

        our_roles = node.get ("roles", [])

        for peer_node in sorted (nodes.keys ()):
            if peer_node == minion_id:
                continue

            peer_node_config = nodes[peer_node]

            # If the remote node isn't a router nor a core-switch, it won't be a peer
            peer_roles = peer_node_config.get ("roles", [])
            peer_role = peer_node_config.get ("role", "")
            if "router" not in peer_roles and "core-switch" != peer_role:
                continue

            # Carry on if neither we nor the peer are a RR
            if "routereflector" not in our_roles and "routereflector" not in peer_roles:
                continue

            # Don't try to set up sessions to VMs/devices which are "planned", "failed", "decomissioning" and "inventory"
            if peer_node_config.get ("status", "") not in [ "", "active", "staged", "offline" ]:
                continue

            for af in AFs:
                # Only generate a session for this AF if the peer has a primary IP for it
                if af not in peer_node_config["primary_ips"]:
                    continue

                peer_config = {
                    # mangle . and - to _ to make bird happy
                    "node" : peer_node,
                    "ip" : peer_node_config["primary_ips"][af].split("/")[0],
                    "rr_client" : False,
                }

                if "routereflector" in our_roles and "routereflector" not in peer_roles:
                    peer_config["rr_client"] = True

                peers[af].append (peer_config)

        return {
            "routing.bgp.internal.peers" : peers,
        }

        