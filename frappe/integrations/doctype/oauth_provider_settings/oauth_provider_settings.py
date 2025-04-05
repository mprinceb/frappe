# Copyright (c) 2015, Frappe Technologies and contributors
# License: MIT. See LICENSE

import base64
import datetime
import json
import os
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from jwt.utils import base64url_encode

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import now_datetime, add_days, getdate


class OAuthProviderSettings(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		skip_authorization: DF.Literal["Force", "Auto"]
		jwks_enabled: DF.Check
		jwks_key_id: DF.Data
		jwks_private_key: DF.Code
		jwks_public_key: DF.Code
		jwks_expiry: DF.Datetime
	# end: auto-generated types
	
	def validate(self):
		if self.jwks_enabled and not self.jwks_private_key:
			self.generate_keys()
			
	def generate_keys(self):
		"""Generate a new RSA key pair for JWKS"""
		# Generate private key
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
			backend=default_backend()
		)
		
		# Get private key in PEM format
		private_pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		).decode('utf-8')
		
		# Get public key in PEM format
		public_key = private_key.public_key()
		public_pem = public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		).decode('utf-8')
		
		# Generate key ID
		kid = str(uuid.uuid4())
		
		# Set expiry date (30 days from now by default)
		expiry = add_days(now_datetime(), 30)
		
		# Save the key information
		self.jwks_private_key = private_pem
		self.jwks_public_key = public_pem
		self.jwks_key_id = kid
		self.jwks_expiry = expiry
		
	def get_jwks(self):
		"""Return the JWKS in the standard format"""
		if not self.jwks_enabled or not self.jwks_public_key:
			return {"keys": []}
			
		# Parse the public key to get components
		public_key = serialization.load_pem_public_key(
			self.jwks_public_key.encode('utf-8'),
			backend=default_backend()
		)
		
		# Get the key components
		numbers = public_key.public_numbers()
		
		# Create the JWK
		jwk = {
			"kty": "RSA",
			"use": "sig",
			"kid": self.jwks_key_id,
			"n": base64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8'),
			"e": base64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8'),
			"alg": "RS256",
		}
		
		return {"keys": [jwk]}


def get_oauth_settings():
	"""Returns oauth settings"""
	settings = frappe.get_doc("OAuth Provider Settings")
	
	return frappe._dict({
		"skip_authorization": settings.skip_authorization,
		"jwks_enabled": settings.jwks_enabled,
		"jwks_key_id": settings.jwks_key_id if settings.jwks_enabled else None,
		"jwks_private_key": settings.jwks_private_key if settings.jwks_enabled else None,
		"jwks_public_key": settings.jwks_public_key if settings.jwks_enabled else None,
	})


def check_jwks_key_rotation():
	"""Check if the JWKS key is about to expire and rotate if needed
	
	This function is meant to be scheduled daily via the scheduler.
	"""
	try:
		settings = frappe.get_doc("OAuth Provider Settings")
		
		if not settings.jwks_enabled:
			return
			
		# Check if key exists and is about to expire (within 5 days)
		current_date = getdate()
		expiry_date = getdate(settings.jwks_expiry)
		days_to_expiry = (expiry_date - current_date).days
		
		if days_to_expiry <= 5:
			frappe.log_error("JWKS key is about to expire. Generating new key.", "JWKS Key Rotation")
			settings.generate_keys()
			settings.save()
			frappe.db.commit()
	except Exception as e:
		frappe.log_error(f"Error in JWKS key rotation: {str(e)}", "JWKS Key Rotation")
