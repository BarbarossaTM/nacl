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

}
