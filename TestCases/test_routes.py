# Request module allows us to use API methods
import requests
import pytest
import json
from flask import jsonify
from json import dumps

BASE ="http://localhost:5000/"

def test_encrypt_decrypt_endpoints():
	mock_encrypt_request_data = { 
	"identifier": "Engineer1",
	"name1": "John", 
	"name2": "Doe", 
	"age": "20" 
	}

	# Send POST request to encrypt endpoint
	response = requests.post(BASE + "encrypt", data=mock_encrypt_request_data)

	# Assert correct response from encryption endpoint
	assert response.status_code == 201

	# Parse the Response from the Encrypt endpoint and pass values to decrypt request json
	reponse_body = response.json()
	identifier = reponse_body['data']['identifier']
	name1 = reponse_body['data']['name1']
	name2 = reponse_body['data']['name2']
	age = reponse_body['data']['age']

	mock_decrypt_request_data = { 
		"identifier": {identifier},
		"name1": {name1}, 
		"name2": {name2}, 
		"age": {age} 
	}

	# Send POST request to decrypt endpoint with results of encrypt
	response = requests.post(BASE + "decrypt", data=mock_decrypt_request_data)
	response_body = response.json()
	decrypt_response_data = response_body['data']

	# Assess whether data has been encrypted and decrypted correctly
	assert decrypt_response_data == mock_encrypt_request_data

	assert response.status_code == 201


def test_sign_verify_endpoints():
	mock_sign_request_data = { 
	    "identifier": "Engineer1",
	    "name1": "John", 
	    "name2": "Doe", 
	    "age": "20" 
	}

	# Send POST request to sign endpoint
	response = requests.post(BASE + "sign", data=mock_sign_request_data)

	# Assert correct response from sign endpoint
	assert response.status_code == 201

	# Parse the Response from the sign endpoint and pass values to verify request json
	reponse_body = response.json()
	message = reponse_body['message']
	signature = reponse_body['data']

	assert message == "JSON payload signed with HASH"

	# Prepare data for verify endpoint POST request
	mock_verify_request_data = {
    "signature": signature,
    "data":[
        {
            "identifier": "Engineer1",
            "name1": "John", 
            "name2": "Doe", 
            "age": "20" 
        }
        ]
	}
	
	# # Send POST request to verify endpoint with result from sign
	response = requests.post(BASE + "verify", json=mock_verify_request_data)

	print("response from verify endpoint")
	print(response)

	response = response.json()

	assert response == 204


def test_RSAencrypt_RSAdecrypt_endpoints():
	mock_sign_request_data = { 
    "identifier": "Engineer1",
    "name1": "John", 
    "name2": "Doe", 
    "age": "20" 
}
	# Send POST request to sign endpoint
	response = requests.post(BASE + "signRSA", json=mock_sign_request_data)

	# Assert correct response from sign endpoint
	assert response.status_code == 201

	# Parse the Response from the Sign endpoint and pass values to verify request json
	reponse_body = response.json()
	message = reponse_body['message']

	assert message == "JSON payload signed with private key"

	signature = reponse_body['data']

	mock_decrypt_request_data = {
    "signature": signature,
     "data": [
        {
            "identifier": "Engineer1",
            "name1": "John", 
            "name2": "Doe", 
            "age": "20" 
        }
     ]
	}

	# Send POST request to decrypt endpoint with results of encrypt
	response = requests.post(BASE + "verifyRSA", json=mock_decrypt_request_data)

	# assert True == True
	assert response.json() == 204
	








