import base64
import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
    AESCCM,
    AESSIV,
    AESOCB3
)

# ==========================
# DERIVACIÓN DE CLAVE
# ==========================

def derivar_clave(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )

    return kdf.derive(password.encode())

def derivar_clave_siv(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=64,
        n=2**14,
        r=8,
        p=1
    )

    return kdf.derive(password.encode())

# ==========================
# AES-256-GCM
# ==========================

def cifrar_aes(texto, password):
    salt = os.urandom(16)
    clave = derivar_clave(password, salt)

    nonce = os.urandom(12)

    aes = AESGCM(clave)

    cifrado = aes.encrypt(
        nonce,
        texto.encode(),
        None
    )

    return base64.b64encode(
        salt + nonce + cifrado
    ).decode()


def descifrar_aes(datos, password):
    datos = base64.b64decode(datos)

    salt = datos[:16]
    nonce = datos[16:28]
    cifrado = datos[28:]

    clave = derivar_clave(password, salt)

    aes = AESGCM(clave)

    texto = aes.decrypt(
        nonce,
        cifrado,
        None
    )

    return texto.decode()


# ==========================
# CHACHA20-POLY1305
# ==========================

def cifrar_chacha(texto, password):
    salt = os.urandom(16)

    clave = derivar_clave(password, salt)

    nonce = os.urandom(12)

    cipher = ChaCha20Poly1305(clave)

    cifrado = cipher.encrypt(
        nonce,
        texto.encode(),
        None
    )

    return base64.b64encode(
        salt + nonce + cifrado
    ).decode()


def descifrar_chacha(datos, password):
    datos = base64.b64decode(datos)

    salt = datos[:16]
    nonce = datos[16:28]
    cifrado = datos[28:]

    clave = derivar_clave(password, salt)

    cipher = ChaCha20Poly1305(clave)

    texto = cipher.decrypt(
        nonce,
        cifrado,
        None
    )

    return texto.decode()


# ==========================
# AES-CCM
# ==========================

def cifrar_aesccm(texto, password):
    salt = os.urandom(16)

    clave = derivar_clave(password, salt)

    nonce = os.urandom(13)

    cipher = AESCCM(clave)

    cifrado = cipher.encrypt(
        nonce,
        texto.encode(),
        None
    )

    return base64.b64encode(
        salt + nonce + cifrado
    ).decode()


def descifrar_aesccm(datos, password):
    datos = base64.b64decode(datos)

    salt = datos[:16]
    nonce = datos[16:29]
    cifrado = datos[29:]

    clave = derivar_clave(password, salt)

    cipher = AESCCM(clave)

    texto = cipher.decrypt(
        nonce,
        cifrado,
        None
    )

    return texto.decode()


# ==========================
# AES-SIV
# ==========================

def cifrar_aessiv(texto, password):
    salt = os.urandom(16)

    clave = derivar_clave_siv(password, salt)

    cipher = AESSIV(clave)

    cifrado = cipher.encrypt(
        texto.encode(),
        []
    )

    return base64.b64encode(
        salt + cifrado
    ).decode()


def descifrar_aessiv(datos, password):
    datos = base64.b64decode(datos)

    salt = datos[:16]
    cifrado = datos[16:]

    clave = derivar_clave_siv(password, salt)

    cipher = AESSIV(clave)

    texto = cipher.decrypt(
        cifrado,
        []
    )

    return texto.decode()


# ==========================
# AES-OCB3
# ==========================

def cifrar_ocb(texto, password):
    salt = os.urandom(16)

    clave = derivar_clave(password, salt)

    nonce = os.urandom(12)

    cipher = AESOCB3(clave)

    cifrado = cipher.encrypt(
        nonce,
        texto.encode(),
        None
    )

    return base64.b64encode(
        salt + nonce + cifrado
    ).decode()


def descifrar_ocb(datos, password):
    datos = base64.b64decode(datos)

    salt = datos[:16]
    nonce = datos[16:28]
    cifrado = datos[28:]

    clave = derivar_clave(password, salt)

    cipher = AESOCB3(clave)

    texto = cipher.decrypt(
        nonce,
        cifrado,
        None
    )

    return texto.decode()


# ==========================
# MENÚ
# ==========================

while True:

    print("\n=== SISTEMA DE CIFRADO ===")
    print("1 - AES-256-GCM")
    print("2 - ChaCha20-Poly1305")
    print("3 - AES-CCM")
    print("4 - AES-SIV")
    print("5 - AES-OCB3")
    print("0 - Salir")

    algoritmo = input("Algoritmo: ").strip()

    if algoritmo == "0":
        break

    if algoritmo not in ("1", "2", "3", "4", "5"):
        print("Algoritmo no válido")
        continue

    print("\n1 - Cifrar")
    print("2 - Descifrar")

    accion = input("Acción: ").strip()

    if accion not in ("1", "2"):
        print("Acción no válida")
        continue

    password = input("Contraseña: ")

    if accion == "1":

        texto = input("Texto: ")

        try:

            if algoritmo == "1":
                resultado = cifrar_aes(texto, password)

            elif algoritmo == "2":
                resultado = cifrar_chacha(texto, password)

            elif algoritmo == "3":
                resultado = cifrar_aesccm(texto, password)

            elif algoritmo == "4":
                resultado = cifrar_aessiv(texto, password)

            elif algoritmo == "5":
                resultado = cifrar_ocb(texto, password)

            print("\nResultado:")
            print(resultado)

        except Exception as e:
            print("Error:", e)

    else:

        texto = input("Texto cifrado: ")

        try:

            if algoritmo == "1":
                resultado = descifrar_aes(texto, password)

            elif algoritmo == "2":
                resultado = descifrar_chacha(texto, password)

            elif algoritmo == "3":
                resultado = descifrar_aesccm(texto, password)

            elif algoritmo == "4":
                resultado = descifrar_aessiv(texto, password)

            elif algoritmo == "5":
                resultado = descifrar_ocb(texto, password)

            print("\nResultado:")
            print(resultado)

        except Exception:
            print("Contraseña incorrecta o texto inválido")