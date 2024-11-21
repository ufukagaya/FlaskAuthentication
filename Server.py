from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import hashlib

class Server:
    def __init__(self):
        self.private_key = RSA.import_key(open("private.pem").read())
        self.public_key = RSA.import_key(open("public.pem").read())
        self.cipher = PKCS1_OAEP.new(self.private_key)

    def register_user(self, username, hashed_password, otp):
        if self.validate_user(username, hashed_password):
            return False
        encrypted_data = self.encrypt_data(f"{username};{hashed_password};{otp}")
        with open("database.txt", "a") as file:
            file.write(encrypted_data + '\n')

    def validate_user(self, username, hashed_password):
        with open("database.txt", "r") as file:
            for line in file:
                decrypted_data = self.decrypt_data(line.strip())
                fields = decrypted_data.split(';')

                # Satır formatını kontrol et
                if len(fields) != 4:
                    print(f"Invalid line format: {decrypted_data}")  # Hatalı satırı loglayabilirsiniz
                    continue

                db_username, db_password, db_otp, counter = fields

                if db_username == username and db_password == hashed_password:
                    return True
        return False

    def generate_otp(self, username):
        seed = hashlib.sha256(username.encode()).hexdigest()
        otp = self.generate_hash_chain(seed, 100)
        return otp[0]

    def validate_otp_and_update(self, username):
        with open("database.txt", "r") as file:
            lines = file.readlines()

        updated = False
        with open("database.txt", "w") as file:
            for line in lines:
                decrypted_data = self.decrypt_data(line.strip())
                db_username, db_password, db_otp = decrypted_data.split(';')

                if db_username == username:
                    new_otp = self.generate_hash_chain(db_otp, 1)[0]
                    encrypted_data = self.encrypt_data(f"{username};{db_password};{new_otp}")
                    file.write(encrypted_data + '\n')
                    updated = True
                else:
                    file.write(line)
        return updated

    def generate_hash_chain(self, seed, n):
        chain = [seed]
        for _ in range(n):
            hash_obj = SHA256.new(chain[-1].encode())
            chain.append(hash_obj.hexdigest())
        return chain

    def encrypt_data(self, data):
        cipher = PKCS1_OAEP.new(self.public_key)
        return cipher.encrypt(data.encode()).hex()

    def decrypt_data(self, data):
        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted = cipher.decrypt(bytes.fromhex(data)).decode()
        return decrypted
