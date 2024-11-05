from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
import os

# Key generation
def generate_keys():
    # Server private key
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Server public key
    server_public_key = server_private_key.public_key()

    # Client private key (financial entity)
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Client public key
    client_public_key = client_private_key.public_key()

    return server_private_key, server_public_key, client_private_key, client_public_key

# Encryption of payment data
def encrypt_data(public_key, data):
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

# Decryption of payment data
def decrypt_data(private_key, encrypted_data):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

# Digital signature for authenticity
def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Signature verification
def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Generation of a hash for data integrity
def generate_hash(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

# Hash verification
def verify_hash(original_hash, data):
    new_hash = generate_hash(data)
    return new_hash == original_hash

# Payment data sending simulation
def payment_system(payment_data):
    # Key generation for server and client
    server_private_key, server_public_key, client_private_key, client_public_key = generate_keys()
    
    # Step 1: Encrypt payment data with the client's public key
    encrypted_data = encrypt_data(client_public_key, payment_data)
    
    # Step 2: Sign the encrypted data with the server's private key for authenticity
    signature = sign_data(server_private_key, encrypted_data)
    
    # Step 3: Generate a hash of the encrypted data to ensure its integrity
    data_hash = generate_hash(encrypted_data)
    
    # Simulate receiving data on the client side
    print("---- Sending data to client ----")
    
    # Step 4: Verify the server's signature
    authenticity = verify_signature(server_public_key, signature, encrypted_data)
    print("Data authenticity:", authenticity)
    
    # Step 5: Verify the integrity of the data using the hash
    integrity = verify_hash(data_hash, encrypted_data)
    print("Data integrity:", integrity)
    
    # Step 6: Decrypt the data if authenticity and integrity are valid
    if authenticity and integrity:
        decrypted_data = decrypt_data(client_private_key, encrypted_data)
        print("Decrypted data:", decrypted_data.decode())
    else:
        print("Error: Payment data has been compromised.")

# Example of payment data (example string converted to bytes)
payment_data = b"Card number: 1234-5678-9012-3456; Expiration: 12/24; CVV: 123"

# Execute the payment system
payment_system(payment_data)

