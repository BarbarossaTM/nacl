#!/usr/bin/python3
#
# Maximilian Wilhelm <max@sdn.clinic>
#  --  Sat 15 Apr 2023 02:59:16 AM CEST
#

class NaclResponse:
	def __init__(self, value, code = 200):
		self.value = value
		self.code = code
