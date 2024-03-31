#!/usr/bin/python3
#
# Maximilian Wilhelm <max@rfc2324.org>
#  --  Sun 17 Mar 2019 09:31:13 PM CET
#

from werkzeug.exceptions import InternalServerError

class NaclError (Exception): pass

class CacheError (NaclError): pass
class ConfigError(NaclError): pass
class ModuleError(NaclError): pass
class NetboxError (NaclError): pass

class DeveloperError (InternalServerError): pass
