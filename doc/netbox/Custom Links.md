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
