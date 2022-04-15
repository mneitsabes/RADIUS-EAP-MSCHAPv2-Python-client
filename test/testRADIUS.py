import unittest
from radius_eap_mschapv2.RADIUS import RADIUS


class TestRADIUS(unittest.TestCase):
	def test_RADIUS__init__(self):
		r = RADIUS("localhost", "mySuperSecret", "127.0.0.1", "nasName")
		self.assertTrue(hasattr(r, "server"))
		self.assertTrue(hasattr(r, "secret"))
		self.assertTrue(hasattr(r, "timeout"))
		self.assertTrue(hasattr(r, "port"))
		self.assertTrue(hasattr(r, "nas_ip_address"))
		self.assertTrue(hasattr(r, "nas_identifier"))
		self.assertTrue(hasattr(r, "identifier"))
