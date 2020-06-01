{
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

		"patchpanel" : {
			"manufacturer" : "telegrtner",
			"device_type" : "patchpanel",
			"device_role" : "patchpanel"
		},

		"surge" : {
			"manufacturer" : "ubnt",
			"device_type" : "surge-protector",
			"device_role" : "surge-protector"
		}
	},

	"defaults" : {
		"interfaces" : {
			"by_name" : {
				"anycast_srv" : {
					"link-type": "dummy"
				},
				"srv" : {
					"link-type": "dummy"
				}
			}
		}
	}

}
