{
        "redis_host" : "localhost",
	"redis_port" : "6379",

	"netbox" : {
		"url" : "http://10.23.42.80:8080/",
		"auth_token": "0815decaf2342netbox4711"
	}

	"blueprints" : {
		<name>: {
			"manufacturer" : <slug>,
			"device_type" : <slug>,
			"device_role" : <slug>
		},

		"surge" : {
			"manufacturer" : "ubnt",
			"device_type" : "surge-protector",
			"device_role" : "surge-protector"
		}
	}

	"tags" : {
		"interface" : {
			"batman_connect_sites" : {
				"match" : {
					"re": "^batman_connect_(.*)$"
					"params" : 1,
				},
				"set" : {
					"field" : "batman_connect_sites",
					"type" : "list"
				}
			},

			"batman_iface" : {
				"match" : {
					"re" : "^batman_iface_(.*)$",
					"params" : 1
				},
				"set" : [
					{
						"field" : "type",
						"value" : "batman_iface"
					},
					{
						"field" : "site"
					}
				]
			},

			"mesh_breakout" : {
				"match" : {
					"re" : "^mesh_breakout_(.*)$",
					"params" : 1
				},
				"set" : [
					{
						"field" : "type",
						"value" : "mesh_breakout"
					},
					{
						"field" : "site"
					}
				]
			}


			"dhcp" : {
				"match" : {
					"name": "dhcp"
				},
				"set" : {
					"field" : "method",
					"value" : "dhcp"
				}
			},

			"status" : {
				"match" : {
					"name" : "plannend"
				},
				"set" : {
					"field" : "status",
					"value" : "planned",
					"default" : "active"
				}
			}
		}
	}

}
