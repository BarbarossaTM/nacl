# NACL ext_pillar module

NACL is ment to be used as a middle layer between Salt and Netbox.
The architecture consists of the NACLd which will query all relevant data from
Netbox and mangle (and cache) it so that is's usefull from a Salt point of view.

NACLd provide a REST API which shall be used by a Salt ext_pillar module to query
the mangled data. That's nacl.py file in this directory.

To activate ext_pillar modules on your Salt master, create a directory where extension
modules shall live on the server (e.g. */srv/salt/modules*) and create a *pillar* subdirectory
within the modules directory (e.g. */srv/salt/modules/pillar*).
Place the nacl.py file in the *pillar* subdirectory.

Now edit the */etc/salt/master* configuration file and uncomment the *extension_modules*
config item (if no present already, then use the configure path ;-)).

    # Directory for custom modules. This directory can contain subdirectories for
    # each of Salt's module types such as "runners", "output", "wheel", "modules",
    # "states", "returners", etc.
    #extension_modules: <no default>
    extension_modules: /srv/salt/modules

