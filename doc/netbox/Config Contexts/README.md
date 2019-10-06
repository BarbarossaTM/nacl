# Config Contexts

Netbox provides [Config Contexts](https://github.com/netbox-community/netbox/blob/develop/docs/additional-features/context-data.md)
to store configuration data for which netbox itself doesn't have attributes or fields. This comes in handy for storing SSH keys
or additional roles of devices and VMs.

As netbox currently lacks support for bridges and tunnel, we'll have to use it to store those configuration parts, too.

Each file in this directory contains the definition of one config context which NACL relies upon.
