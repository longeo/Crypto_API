import markdown
import os
import json
import base64
import binascii

# Packages for symmetric encryption
import cryptography
from cryptography.fernet import Fernet
# Packages for signing with Hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# Packages for Signing and validating with RSA
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

# Import the framework
from flask import Flask, jsonify
from flask_restful import Api, Resource, reqparse, request

# Create an instance of Flask
app = Flask(__name__)

# Create the API
api = Api(app)

global config_array 

def parse_request():
	"""Parse FLask Request json and returns dictionary"""
	"""Request for sign endpoint and sign_RSA endpoint are the same"""

	parser = reqparse.RequestParser()
	# Requests must contain these fields
	parser.add_argument('identifier', required=True)
	parser.add_argument('name1', required=True)
	parser.add_argument('name2', required=True)
	parser.add_argument('age', required=True)

	return parser.parse_args()

def parse_request_verify():
	"""Parse request for verification"""

	parser = reqparse.RequestParser()
	# Requests must contain these fields
	parser.add_argument('signature', required=True)
	parser.add_argument('data',type=dict, required=True)

	return parser.parse_args()

def get_RSA_keys():
	key_pair_filename = "RSA_keys.pem"
	pub_key_filename = "RSA_pub_key.pem"

	# Checks if RSA key pair exists on disk if it doesn't, generate new key pair
	if not(os.path.exists(key_pair_filename) or os.path.exists(pub_key_filename)):
		# Generate private RSA key
		keyPair = RSA.generate(bits=1024)

		# Write private RSA key pair to file for signing
		print("Creating key pair location")
		file = open(key_pair_filename,'wb')
		file.write(keyPair.exportKey('PEM'))
		file.close()

		# Write public RSA key to file for verification
		print("Creating public key location")
		file = open(pub_key_filename,'wb')
		file.write(keyPair.publickey().exportKey('PEM'))
		file.close()
	
	# Read RSA private key
	file = open(key_pair_filename,'rb')
	keyPair = RSA.importKey(file.read())
	file.close()
	
	# Read RSA public key
	file = open(pub_key_filename,'rb')
	key = RSA.importKey(file.read())
	pub_key = key.publickey()
	file.close()

	return keyPair, pub_key

def get_AES_key():
	filename = "AES_key.key"

	# Checks if key exists on disk, if it doesn't, generate new key
	if not os.path.exists(filename):
		print("Creating Key for AES encryption")
		key = Fernet.generate_key()
		file = open(filename,'wb')
		file.write(key)
		file.close()
	
	file = open(filename,'rb')
	key = file.read()
	file.close()
	
	return key

def encrypt_req(key, request_obj):
	"""Take JSON as parameter and encryts field values"""

	# Generate fernet based on key 
	fernet = Fernet(key)

	# Convert request JSON to string, encode it and encrypt
	request_obj_bytes = bytes(str(request_obj),'utf-8')                     	                     
	request_obj = fernet.encrypt(request_obj_bytes).decode("utf-8")

	return request_obj

def encrypt_req_fields(key, request_obj):
	"""Take JSON as parameter and encryts entire payload"""

	# Generate fernet based on key

	# # Encrypt each field in request JSON
	# for field in request_obj:
	# 	field_bytes = bytes(request_obj[field],'utf-8')                     	                     
	# 	request_obj[field] = fernet.encrypt(field_bytes).decode("utf-8")

	encrypt_field(key, request_obj)


	return request_obj

def encrypt_field(key, request_object):
	fernet = Fernet(key)

	for field in request_object:
		if field in config_array:	
			field_bytes = bytes(request_object[field],'utf-8')                     	                     
			request_object[field] = fernet.encrypt(field_bytes).decode("utf-8")

		if isinstance(request_object[field], list) or isinstance(request_object[field], dict):
			encrypt_field(key, request_object[field])


def decrypt_req(key, request_obj):
	# Returns JSON with all fileds decrypted
	# Generate fernet based on key (should i do this in get_key?)
	fernet = Fernet(key)

	for field in request_obj:
		# JSON values must be in byte format in order to encrypt
		field_bytes = bytes(request_obj[field],'utf-8') 
		try:                    
			request_obj[field] = fernet.decrypt(field_bytes).decode("utf-8")
		except cryptography.fernet.InvalidToken:
			print("Did not decrypt:")
			print(field)

	return request_obj

def get_salt():
	filename = "salt.txt"

	# Create and save hash if one doesn't exist
	if not os.path.exists(filename):
		salt = os.urandom(16)
		f = open(filename, "wb")
		f.write(salt)
		f.close()	

	f = open(filename, "rb")
	salt = f.read()
	f.close()	

	return salt

def sign(salt, request_obj):
	# Convert request object to string and then to bytes 
	request_obj_bytes = str(request_obj).encode("utf-8")

	# Instantiate HASH object
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
	)

	# Calculate signature using hash object 
	signature = kdf.derive(request_obj_bytes)

	# Encode bytes with url safe alphabet encoding
	signature = base64.urlsafe_b64encode(signature)
	
	# Decode bytes to string and return string
	return signature.decode("utf-8")

def verify_signature(AES_key, salt, request_obj):
	# First ensure request object's data field is fully decrypted (using AES sym. encryp.)
	request_obj_data = request_obj["data"]
	request_obj_data = decrypt_req(AES_key, request_obj_data)

	# Sign request data payload 
	payload_signature = sign(salt, request_obj_data)

	# Then extraxt signature from signature field of request
	signature = request_obj["signature"]

	# Compare signature calculated from data payload with received signature
	if payload_signature == signature:
		print ("Hash Signature Verified!")
		return True
	else:
		print ("Hash Signature NOT Verified!")
		return False

def sign_RSA(keyPair, request_obj):

	# Convert request object to string and then to byte stream
	request_obj = str(request_obj).encode("utf-8")

	# Sign request object with private key
	hash = SHA256.new(request_obj)
	signer = PKCS115_SigScheme(keyPair)
	signature  = signer.sign(hash)

	# Decode signature for JSON response
	signature = base64.urlsafe_b64encode(signature).decode("utf-8")

	return signature
	
def verify_RSA(AES_key, RSA_keys, request_obj):
	# Ensure that all fields are decrypted in request object
	request_obj_data = request_obj["data"]
	request_obj_data = decrypt_req(AES_key, request_obj_data)

	# Convert payload data into string and then into byte stream 
	request_obj_data = str(request_obj_data).encode("utf-8")

	# Extract signature recieved in request object (data allegedly signed with private key)
	signature_private = request_obj["signature"]
	signature_private = base64.urlsafe_b64decode(signature_private.encode("utf-8"))

	# Verify valid PKCS#1 v1.5 signature (RSAVP1)
	hash = SHA256.new(request_obj_data)
	verifier = PKCS115_SigScheme(RSA_keys[1])
	try:
	    verifier.verify(hash, signature_private)
	    print("Signature is valid.")
	    return True
	except:
	    print("Signature is invalid.")
	    return False

@app.route("/")
def index():
	"""Present some documentation"""

	# Open the README file
	with open(os.path.dirname(app.root_path) + '/README.md', 'r') as markdown_file:

		# Read the content of the file
		content = markdown_file.read()
 
		# Convert to HTML
		return markdown.markdown(content)


class Encrypt(Resource):
	def post(self):
		#Get flask request in dictionary format
		# request_dict = parse_request()

		request_object = request.get_json()

		key = get_AES_key()

		return {'message': 'Request Encrypted', 'data': encrypt_req_fields(key, request_object)}, 201


class Decrypt(Resource):
	def post(self):
		request_dict = parse_request()

		key = get_AES_key()

		return {'message': 'Request Decrypted', 'data': decrypt_req(key, request_dict)}, 201


class Sign(Resource):
	def post(self):
		request_dict = parse_request()

		salt = get_salt()

		return {'message': 'JSON payload signed with HASH', 'data': sign(salt, request_dict)}, 201


class Verify(Resource):
	def post(self):
		request_dict = parse_request_verify();

		salt = get_salt()
		AES_key = get_AES_key()

		# Decrypt signature field using saved hash salt. Check if it matches plaintext payload.
		if verify_signature(AES_key, salt, request_dict):
			return 204
		else:
			return 400


class SignRSA(Resource):
	def post(self):
		request_dict = parse_request()

		RSA_keys = get_RSA_keys()

		# Sign JSON request with private key
		return {'message': 'JSON payload signed with private key', 'data': sign_RSA(RSA_keys[0], request_dict)}, 201


class VerifyRSA(Resource):
	def post(self):
		# VerifyRSA reveives:
		# 	- plaintext payload
		# 	- signature that has been signed with a private key
		# It checks whether the public key unlocks the signature correctly

		request_dict = parse_request_verify()

		AES_key = get_AES_key()
		RSA_keys = get_RSA_keys()

		# Return 204 if the JSON request has been signed by the correct key. 
		if verify_RSA(AES_key, RSA_keys, request_dict):
			return 204
		else:
			return 400

class Config(Resource):
	def put(self):
		global config_array

		request_object = request.get_json();
		
		config_array = request_object["fields"]

		print(config_array)

		return config_array


api.add_resource(Encrypt, '/encrypt')
api.add_resource(Decrypt, '/decrypt')
api.add_resource(Sign, '/sign')
api.add_resource(Verify, '/verify')
api.add_resource(SignRSA, '/signRSA')
api.add_resource(VerifyRSA, '/verifyRSA')
api.add_resource(Config, '/config')








