# NACL

NACL is the Netbox Abstration / Automation & Caching Layer for [Freifunk Hochstift Salt Stack](https://github.com/FreifunkHochstift/ffho-salt-public).

We're managing all our Linux nodes inside the Freifunk Hochstift network within [NetBox](https://github.com/netbox-community/netbox).
This includes physical devices as well as virtual machines including host-side VM interface configuration.

In the future this shall be extended to regular networking kit (mainly switches) and wireless equipment (e.g. for wireless backbone links).

Those devices are documentated including
 * their OS (platform)
 * network interfaces and connections including Wireguard tunnels
 * IP addresses and their VRFs
 * SSH keys and SSL host cert/keys (stored in config contexts)
 * roles of the device

NACL has a caching layer to speed up requests from Salt and will cache the last successfully fetch data set in memory until the next refresh was successful. 
By default NetBox data will be refreshed every 1 minute after the last refresh ended.

## Requirements

### Python environment

NACL requires the `requests` and `werkzeug` Python libraries.
On a Debian system you can install them via:

    apt-get install python3-requests python3-werkzeug

### NetBox

NACL is using the NetBox API as exposed by version 3.4.7.
As NetBox does minor and even major breaking changes from time to time, NACL will not be compatible with much older or potentially newer versions.
