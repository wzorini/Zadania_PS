from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import os


# Generowanie klucza prywatnego (jeśli nie istnieje)
def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def save_private_key(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))


# Wczytywanie klucza prywatnego z pliku
def load_private_key(filename):
    with open(filename, "rb") as key_file:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        return load_pem_private_key(key_file.read(), password=None)


# Podpisywanie pliku
def sign_file(private_key, input_file, output_signature):
    # Wczytaj dane z pliku
    with open(input_file, "rb") as f:
        data = f.read()


    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(output_signature, "wb") as f:
        f.write(signature)



PRIVATE_KEY_FILE = "private_key.pem" # Klucz prywatny
INPUT_FILE = "Plik.txt"  # Plik do podpisania
SIGNATURE_FILE = "dane.sig"  # Plik podpisu


if not os.path.exists(PRIVATE_KEY_FILE):
    print("Generowanie nowego klucza prywatnego...")
    private_key = generate_private_key()
    save_private_key(private_key, PRIVATE_KEY_FILE)
else:
    print("Wczytywanie istniejącego klucza...")
    private_key = load_private_key(PRIVATE_KEY_FILE)

print("Podpisywanie pliku...")
sign_file(private_key, INPUT_FILE, SIGNATURE_FILE)

print(f"Plik '{INPUT_FILE}' został podpisany!")
print(f"Klucz prywatny: {PRIVATE_KEY_FILE}")
print(f"Podpis cyfrowy: {SIGNATURE_FILE}")