# NACL

NACL is the Netbox Abstration / Automation & Caching Layer for [Freifunk Hochstift Salt Stack](https://github.com/FreifunkHochstift/ffho-salt-public).

The aim is to manage all nodes of the Freifunk Hochstift network within [NetBox](https://github.com/digitalocean/netbox).
This includes physical devices as well as virtual machines (including their ressources and placement on VM hosts).
Physical devices could be general Linux boxes which run a Salt minion, switches (which might be managed by NAPALM in the future) or wireless backbone devices.

Those devices will be documentated including
 * their OS (platform)
 * network interfaces and connections
 * IP addresses and their VRFs
 * SSH keys and SSL host cert/keys (stored in config contexts)
 * roles of the device

The aim is to remove all those information from Salt pillar and use NetBox + NACL as the only source of truth for all devices.
