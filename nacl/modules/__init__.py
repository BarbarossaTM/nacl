#!/usr/bin/python3
#
# Maximilian Wilhelm <max@sdn.clinic>
#  --  Thu 15 Feb 2024 22:51:33 CET
#

from typing import Optional
import inspect
import logging

from nacl.errors import ConfigError, ModuleError

class BaseModule:
    """ The NACL BaseModule - all modules need to inherit this."""

    def __init__(self, module_name: str, module_params: dict, nacl_obj, logger: logging.Logger):
        """ Set up a NACL Module.

        Parameters
        ----------
            module_name: str
                The name of this module.
            modules_params: dict
                The 'params' section from the module's dict in NACL's configuration (empty dict if not present).
            nacl_obj: nacl.app.Nacl
                The instanciated Nacl App this module is being run from, can be used to query further details.
            logger: logging.Logger:
                A logger to be used by this module.
        """
        self._name = module_name
        self.params = module_params
        self.nacl = nacl_obj
        self.nacl_config = self.nacl.get_config()
        self.log = logger

        self.log.info(f"Initializing module {self._name}...")

    def name(self) -> str:
        """Return the name of this module."""
        return self._name

    def should_run(self, node_config: dict) -> bool:
        """Returns whether this module should run for the given node_config.

        Parameters
        ----------
        node_config:
            A node_config dict containing the NACL node configuration generated so far.

        Returns
        -------
            bool
        """
        raise NotImplemented("The should_run() method needs to be implemented by each modules!")

    def run(self, nodes: dict, node_id: str) -> Optional[dict]:
        """Execute the module for the given node_id.

        Parameters
        ----------
        nodes:
            A dictionary containing all node_configs by their respective node_id.

        Returns
        -------
        dict, optional:
            A dictionary containing the configuration items generated by this module.
            Items are identified by a hierarchical key with elements separated by dots,
            e.g. routing.bgp.internal.peers or wireguard.
            A return value of None may be used to indicate that no configuration has been generated.
        """
        raise NotImplemented("The run() method needs to be implemented by each module!")


class ModuleManager:
    def __init__(self, nacl_obj, logger: logging.Logger):
        """ Set up a new ModuleManager with the given modules_config and logger.

        Parameters
        ----------
            nacl_obj: nacl.app.Nacl
                The instanciated Nacl App this is being run from, can be used to query further details.
            logger: logging.Logger
                A logging.Logger object which the ModuleManager and Modules shall use for logging.
        """
        self.nacl = nacl_obj
        self.modules_config = nacl_obj.get_config().get('modules', [])
        self.log = logger

        self._modules = []
        hook_num = 0

        if not isinstance(self.modules_config, list):
            raise ConfigError(f"modules_config not a list, but {type(self._modules_config)}")

        for module_cfg in self.modules_config:
            hook_num += 1

            if not "name" in module_cfg:
                raise ConfigError(f"'name' attribute missing for configuration for module #{hook_num}!")

            self._register_module(module_cfg)

    def _register_module(self, module_cfg) -> None:
        module_name = module_cfg["name"]

        # Module may or may not have parameters
        module_params = module_cfg.get("params", {})

        try:
            python_module = __import__(f"nacl.modules.{module_name}", {}, {}, ['*'])
        except ModuleNotFoundError as e:
            raise ModuleError(f"Error loading module {module_name}: {str(e)}")

        module_file_path = python_module.__file__.replace ('.pyc', '.py')
        self.log.debug(f"Loaded module {module_name} defined in {module_file_path}.")

        # Check if there is a 'Module' class defined in the loaded module
        if not 'Module' in [x[0] for x in inspect.getmembers(python_module, inspect.isclass)]:
            raise ModuleError(f"Module {module_name} defined in {module_file_path} does not define a 'Module' class.")

        # Instanciate module
        try:
            module_obj = python_module.Module(module_name, module_params, self.nacl, self.log)
        except AttributeError as e:
            raise ModuleError(f"module {module_name}: Missing 'Module' class? - {str(e)}")
        except ConfigError as e:
            raise ModuleError(f"module {module_name}: {str(e)}")
        except Exception as e:
            raise ModuleError(f"module {module_name}: {str(e)}")

        self._modules.append(module_obj)

    def _store_results(self, device_config: dict, additional_config: dict, module_obj):
        for key, val in additional_config.items():
            level = device_config

            # Items within result dictionaries of modules' run methods are identified by a hierarchical key
            # with elements separated by dots, e.g. routing.bgp.internal.peers or wireguard.
            # Separate the keys into the hieararchy and the bottom most key.
            if "." in key:
                hierarchy, key = key.rsplit(".", 1)

                for elem in hierarchy.split("."):
                    if elem not in level:
                        level[elem] = {}

                    if not isinstance(level[elem], dict):
                        raise ModuleError(f"Module {module_obj.name()} trying to store sub-key of non-dict item {elem}")

                    level = level[elem]

            if key in level:
                raise ModuleError(f"Module {module_obj.name()} is trying to overwrite configuration item {key}!")

            level[key] = val

    def run_modules(self, nodes_config: dict, node_id: str) -> None:
        """ Run all configured modules for the given nodes_config and node_id.

        Parameters
        ----------
            nodes_config: dict
                Dictionary with configuration data for all nodes.
            node_id: str
                Name of the node configuration should be build for, used as key within nodes_config dict.
        """
        self.log.debug(f"Running modules for node {node_id}...")

        node_config = nodes_config[node_id]

        for module in self._modules:
            if not module.should_run(node_config):
                self.log.debug(f"Skipping module {module.name()} for node {node_id}...")
                continue

            self.log.debug(f"Running module {module.name()} for node {node_id}...")
            res = module.run(nodes_config, node_id)
            if not res:
                self.log.debug(f"No result from module {module.name()} for node {node_id}...")
                continue

            self._store_results(node_config, res, module)
