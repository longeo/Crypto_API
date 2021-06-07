
# Cryptography API

## Description

This is a cryptography API built using Flask micro web framework. 

There are six endpoints: 

	- Encrypt
	- Decrypt
	- Sign
	- Verify
	- SignRSA
	- VerifyRSA


### Note on signature generation and verification endpoints

In the problem description given on the handout, it is asked that signature verification is carried out using the Sign and verify endpoints. My interpretation of the verify endpoint description states that the plaintext payload should be signed to create a cipher-text signature. This should then be compared to the cipher text signature received in the POST request. I don't believe that this is the optimum solution, as most strong signature generators will use an initialisation vector in order to create different cipher text outcomes for identical text. Perhaps, I am misinterpreting the question.

I have implemented this task as described using a hash function with a salt value which is written to the disk. This means cipher-text will always be the same for a given plaintext payload.

As an extra, I created two more endpoints for implementing RSA signature generation and verification, which offers a more secure solution. This works by signing a payload with a private key at the signature endpoint, `signRSA`, and then decrypting the signature using the public key at the verification endpoint, `verifyRSA`. The result is compared with the plaintext payload to either verify or invalidate the key.

Perhaps, this is what you were asking for in the question and I've just misread it.

Let me know if there is any trouble running the project.

**Key Management**
- A private key is generated on startup and written to the disk. This key is used for AES symmetric encryption/decryption.
- A public, private key pair is generated on startup for RSA signature verification. The key-pair is saved to disk.


## Execute API and Test-cases
The server application is run in a docker container binded on port 80. Start the container by navigating to the project root and running
```
docker compose up
```
To run the test-cases, navigate to the root in a separate terminal and run
```
pytest TestCases
```

**Test cases:**
- test1: Encrypt JSON with mock payload. Pass encrypted JSON values to decrypt request JSON. Decrypt result.
- test2: Sign JSON with hash. Pass HASH signature to verify request JSON. Verify result using shared salt value. 
- test3: Sign JSON with RSA private key and verify result using public and original plaintext JSON.


## API Requests and Responses

### Encrypt JSON

**Definition**

`POST /encrypt`

**Arguments**

- `"identifier":string` a globally unique identifier for this object
- `"name1":string` first name field
- `"name2":string` second name field
- `"age":string` age field

At the encrypt endpoint each field of the JSON is encrypted using AES symmetric. The encrypted JSON is sent as a repsonse.

**Response**

- `200 OK` on success

Example response:
```json
{
    "identifier": "gAAAAABgqRZwurrWJJuNkDQD7dlPuL8nDOOhplY6XxM-M5M1PLhH8wGdKiPXcBVOMaiqBdDgbaBu8JKs1WY7If_qDpioT5eCdQ==",
    "name1": "gAAAAABgqRZwPsc6szoBqpv7Ugg9dooFQnEWvuV31bChvB9_24cXtrkdl2fxKazzGYPTh57cexT3a4b-e1TVd5mt04WoFXTNcw==",
    "name2": "gAAAAABgqRZwKEc3tRksYvNsWD7tnLnEC7X3sPU41B0YituSLAgrvVlbKV6z9CVvFehsfYQ-Qpvhm61xHMyilW66puv8Zi7NMQ==",
    "age": "gAAAAABgqRZw7UXp8HUeCJo1LJKsN0WEoTm9ZzYhFPR6BE9LJy19OgsKNdOFCrM3cYY05RwPfHfxFKQ3e5lxsMqgM4HpeMwxwA=="
    }
```

### Decrypt JSON

**Definition**

`POST /decrypt`

**Arguments**

- `"identifier":string` a globally unique identifier for this object
- `"name1":string` first name field
- `"name2":string` second name field
- `"age":string` age field

Decrypts encrypted fields of JSON. If error is raised when trying to decrypt a value, the original value is returned. As this is symmetric encryption a single private key is used for both encryption and decryption.

**Response**

- `200 OK` on success

Example response:
```json
{
    "identifier": "Engineer1",
    "name1": "John",
    "name2": "Doe",
    "age": "20"
}
```
### Sign JSON

**Definition**

`POST /sign`

**Arguments**

- `"identifier":string` a globally unique identifier for this object
- `"name1":string` first name field
- `"name2":string` second name field
- `"age":string` age field

Takes a JSON payload and computes a cryptographic signature for the plaintext payload. The signature is then sent in a JSON response. 

􏰄􏰇􏰑􏰊**Response**

- `200 OK` on success

```json
{
    "message": "JSON payload signed with HASH",
    "data": "LJBKTE62t08HC1cZnoLamdZpFzpbZbtptZXY16m5obw="
}
```

### Verify JSON

**Definition**

`POST /verify`

**Arguments**

- `"signature:string"` JSON hash signature for verification
- `"data":string` JSON payload data to be verified

Takes a JSON plaintext payload and a hash signature. Verifies that the signature belongs to the payload.

􏰄􏰇

**Response**

- `204 No Content` on success
- `400 Bad Request` signature does not match json payload


### SignRSA JSON

**Definition**

`POST /signRSA`

**Arguments**

- `"identifier":string` a globally unique identifier for this object
- `"name1":string` first name field
- `"name2":string` second name field
- `"age":string` age field


-Takes a JSON plaintext payload computes a cryptographic signature for the plaintext payload using the private key. The signature is then sent in a JSON response.

**Response**

- `200 OK` on success

```json
{
    "message": "JSON payload signed with private key",
    "data": "0iAF2oSPY24lU_VAI_FALjTqZGQIJ061tc196_N392sy7PfoHHbL6-0dMuETSJoqoRdc8gwqa0CR-odl65lt4DPsMGQFQUHwtTJr4y1nEk4P64qs1r4LMC-ZmLaQtc9-VoiSBUNWoc1KbiTd90lj9FsCmx42ZN-eSwoA3Zyez-U="
}
```

### VerifyRSA JSON

**Definition**

`POST /verifyRSA`

**Arguments**

- `"signature:string"` JSON RSA signature for verification
- `"data":string` JSON payload data to be verified

􏰄􏰇􏰑􏰊Takes a JSON payload and a RSA signature. Decrypts signature using public key. Verifies resulting decryption against plaintext JSON payload.

**Response**

- `204 No Content` on success
- `400 Bad Request` signature does not match json payload


### Config

Request

-`PUT /config`


```json
{
    "fields": "[PPS, XYZ]"
}
```




