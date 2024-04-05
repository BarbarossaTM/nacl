{
	"netbox" : {
		"url" : "http://10.23.42.80:8080/",
		"auth_token": "0815decaf2342netbox4711"
	}

	"cache": true,

	"defaults": {
		"interfaces": {
			"by_name": {
				"anycast_srv": {
					"link-type": "dummy"
				},
				"srv": {
					"link-type": "dummy"
				}
			}
		}
	},

	"role_map": {
		"edge-router": [
			"router",
			"l3-access",
			"dhcp-server"
		]
	},

	"DNS": {
		"infra_domain": "infra.example.com"
	},

	"modules": [
		{
			"name": "ospf_interfaces"
		},
		{
			"name": "ibgp_peers"
		},
		{
			"name": "wireguard"
		},
		{
			"name": "dhcp_server"
		}
	]
}
