# Custom Links

We started deploying Custom Links to ease administration of devices.

## WebUI for Wireless Backbone Links

As Wireless Backbone Links happen to have issues now and then we need to access the WebUI of the UBNT devices in that case.
Up to now we copied the (primary) IP address of the device in the browsers URL bar and hit return.
This can be achieved much nicer with a custom link which directly points to `https://primary_device_ip`

This can be done by creating a new Custom Link with
 * Name: e.g. `WebUI`
 * Content type `DCIM -> device`
 * Button class of your chosing
 * New window: `checked`
 * Link text: `{% if obj.device_role.slug == 'wbbl' %}WebUI{% endif %}` to only show this link for WBBL devices
 * Link URL `https://{{ obj.primary_ip4.address.ip }}` to directly point to the devices WebUI

### Use the same link for multiple devices

To use the same link for multiple devices it's either possible to check for different things and 'or' the conditions or for example to check for certain platforms:

  {% if obj.platform.name in [ 'AirOS', 'Netonix' ] %}
  WebUI
  {% endif %}

As there may be multiple roles for devices of a given type or platform it seems better to check for the platforms of devices where this link should apply.

More details can be found at https://blog.sdn.clinic/2021/09/custom-links-in-netbox-shortcut-to-device-webuiipmi/
