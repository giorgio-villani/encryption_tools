from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from oslo_utils import encodeutils
import base64


class KeyGenerator:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    @staticmethod
    def generate_string_from_pem(private_key_pem_utf):
        split_key = private_key_pem_utf.split('\n')
        long_string = ''.join(split_key)
        return long_string

    @staticmethod
    def generate_pem_from_string(private_key_string_utf):
        n = 64
        split_key = [private_key_string_utf[i:i + n] for i in range(0, len(private_key_string_utf), n)]
        split_key.append('')
        private_key_pem_utf = '\n'.join(split_key)
        return private_key_pem_utf

    def public_private_key_pair_generate(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    # private specific methods
    def private_pem_generate(self):
        private_key_string = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key_string

    def private_pem_string_generate(self):
        return self.private_pem_generate().decode('utf-8')

    def private_pem_file_write(self):
        with open('keys/private_key.pem', 'wb') as private_file:
            private_pem = self.private_pem_generate()
            private_file.write(private_pem)

    def private_pem_file_read(self):
        with open("keys/private_key.pem", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        self.public_key = self.private_key.public_key()

    # public specific methods
    def public_pem_generate(self):
        public_key_string = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_string

    def public_pem_string_generate(self):
        return self.public_pem_generate().decode('utf-8')

    def public_pem_file_write(self):
        with open('keys/public_key.pem', 'wb') as public_file:
            public_pem = self.public_pem_generate()
            public_file.write(public_pem)

    def public_pem_file_read(self):
        with open("keys/public_key.pem", "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

    # signing and verifying messages
    def sign_message(self, message):
        signed_message = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signed_message

    def verify_message(self, signed_message, message):
        try:
            self.public_key.verify(
                signed_message,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print('Valid Signature')
        except InvalidSignature:
            print('Invalid Signature')

    # encrypting and decrypting (optimial asymmetric encryption padding (OAEP) & mask generation function MGF1)
    def encrypt_message(self, message):
        encrypted = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted)

    def decrypt_message(self, encrypted_message):
        original_message = self.private_key.decrypt(
            base64.b64decode(encrypted_message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message
