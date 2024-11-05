from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
import os

# Generación de claves
def generar_claves():
    # Clave privada del servidor
    clave_privada_servidor = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Clave pública del servidor
    clave_publica_servidor = clave_privada_servidor.public_key()

    # Clave privada del cliente (entidad financiera)
    clave_privada_cliente = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Clave pública del cliente
    clave_publica_cliente = clave_privada_cliente.public_key()

    return clave_privada_servidor, clave_publica_servidor, clave_privada_cliente, clave_publica_cliente

# Cifrado de datos de pago
def cifrar_datos(clave_publica, datos):
    datos_cifrados = clave_publica.encrypt(
        datos,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return datos_cifrados

# Descifrado de datos de pago
def descifrar_datos(clave_privada, datos_cifrados):
    datos_descifrados = clave_privada.decrypt(
        datos_cifrados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return datos_descifrados

# Firma digital para autenticidad
def firmar_datos(clave_privada, datos):
    firma = clave_privada.sign(
        datos,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma

# Verificación de firma
def verificar_firma(clave_publica, firma, datos):
    try:
        clave_publica.verify(
            firma,
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Generación de un hash para la integridad de los datos
def generar_hash(datos):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(datos)
    return digest.finalize()

# Verificación del hash
def verificar_hash(hash_original, datos):
    nuevo_hash = generar_hash(datos)
    return nuevo_hash == hash_original

# Simulación de envío de datos de pago
def sistema_de_pago(datos_de_pago):
    # Generación de claves para el servidor y cliente
    clave_privada_servidor, clave_publica_servidor, clave_privada_cliente, clave_publica_cliente = generar_claves()
    
    # Paso 1: Cifrar los datos de pago con la clave pública del cliente
    datos_cifrados = cifrar_datos(clave_publica_cliente, datos_de_pago)
    
    # Paso 2: Firmar los datos cifrados con la clave privada del servidor para autenticidad
    firma = firmar_datos(clave_privada_servidor, datos_cifrados)
    
    # Paso 3: Generar un hash de los datos cifrados para asegurar su integridad
    hash_datos = generar_hash(datos_cifrados)
    
    # Simulación de recepción de los datos en el cliente
    print("---- Enviando datos al cliente ----")
    
    # Paso 4: Verificar la firma del servidor
    autenticidad = verificar_firma(clave_publica_servidor, firma, datos_cifrados)
    print("Autenticidad de los datos:", autenticidad)
    
    # Paso 5: Verificar la integridad de los datos usando el hash
    integridad = verificar_hash(hash_datos, datos_cifrados)
    print("Integridad de los datos:", integridad)
    
    # Paso 6: Descifrar los datos si la autenticidad y la integridad son válidas
    if autenticidad and integridad:
        datos_descifrados = descifrar_datos(clave_privada_cliente, datos_cifrados)
        print("Datos descifrados:", datos_descifrados.decode())
    else:
        print("Error: Los datos de pago han sido comprometidos.")

# Ejemplo de datos de pago (string de ejemplo convertido a bytes)
datos_de_pago = b"Numero de tarjeta: 1234-5678-9012-3456; Vencimiento: 12/24; CVV: 123"

# Ejecución del sistema de pago
sistema_de_pago(datos_de_pago)
