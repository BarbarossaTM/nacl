#!/usr/bin/python3
#
# Maximilian Wilhelm <max@sdn.clinic>
#  --  Mon 01 Jun 2020 05:36:31 PM CEST
#

import copy
from multiprocessing import Lock
import threading
import time

from nacl.errors import *

class NaclCacheObject(object):
	def __init__(self, name, logger, data_func, update_interval):
		"""
		Set up a new Cache with the given <name>.

		logger is the logging instance to use,
		data_func() a function returning data to be cached,
		update_interval is the time passed to time.sleep() between gathering a new ste of data
		"""
		self.lock = Lock()

		self.name = name
		self.log = logger
		self.data_func = data_func
		self.update_interval = update_interval

		# Initial sync
		self.log.info (f"Doing initial data sync for {name}")
		self._update_data()

		# Start background update thread
		self._stopped = False
		self._update_thread = threading.Thread(target=self._update_runner)
		self._update_thread.start()

	def get_data (self):
		"""
		Return a (deep) copy of the topology data gathered from NetBox
		"""
		self.lock.acquire()
		data = copy.deepcopy(self.data)
		self.lock.release()

		return data

	def stop(self):
		"""
		Stop the cache update thread.
		"""
		self._stopped = True
		self._update_thread.stop()

	def _update_data(self):
		start = time.time()
		try:
			data = self.data_func()
			load_time = time.time() - start
		except Exception as e:
			err = str(e)
			self.log.error(f"Failed to update {self.name} data: {err}!")
			return

		self.lock.acquire()
		self.data = data
		self.timestamp = time.time()
		self.lock.release()

		self.log.info (f"Updated cached data for {self.name}, took {load_time:.2f}s")

	def _update_runner(self):
		while not self._stopped:
			time.sleep (self.update_interval)
			self._update_data()
