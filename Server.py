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
        counter = 1
        encrypted_data = self.encrypt_data(f"{username};{hashed_password};{otp};{counter}")
        with open("database.txt", "a") as file:
            file.write(encrypted_data + '\n')

    def validate_user(self, username, hashed_password):
        with open("database.txt", "r") as file:
            for line in file:
                decrypted_data = self.decrypt_data(line.strip())
                fields = decrypted_data.split(';')

                db_username, db_password, db_otp, counter = fields
                if db_username == username and db_password == hashed_password:
                    return True
        return False

    def generate_otp(self, password):
        seed = hashlib.sha256(password.encode()).hexdigest()
        otp = self.generate_hash_chain(seed, 100)
        return otp[-1]

    def validate_otp_and_update(self, username):
        database_lines = []
        with open("database.txt", "r") as file:
            for line in file:
                decrypted_line = self.decrypt_data(line.strip())
                user_data = decrypted_line.split(";")
                if user_data[0] == username:
                    current_otp = user_data[2]
                    counter = int(user_data[3])

                    print(f"Current OTP: {current_otp}, Counter: {counter}")
                    print("Next: " + self.generate_hash_element(user_data[1], 100 - counter))

                    if current_otp == self.generate_hash_element(user_data[1], 100 - counter + 1):
                        new_otp = self.generate_hash_element(user_data[1], 100 - counter)
                        print(f"New OTP: {new_otp}")
                        seed = user_data[1]
                        otp_chain = [seed]
                        #for debug
                        for i in range(100):
                            seed = SHA256.new(seed.encode()).hexdigest()
                            otp_chain.append(seed)
                        print(otp_chain[100-counter])
                        new_counter = counter + 1
                        updated_data = f"{username};{user_data[1]};{new_otp};{new_counter}"
                        encrypted_line = self.encrypt_data(updated_data)
                        print(f"Updated data: {updated_data}")
                    else:
                        return False
                else:
                    encrypted_line = line.strip()

                database_lines.append(encrypted_line)

        with open("database.txt", "w") as file:
            for line in database_lines:
                file.write(line + "\n")
        return True

    def generate_hash_chain(self, seed, n):
        chain = [seed]
        for _ in range(n):
            hash_obj = SHA256.new(chain[-1].encode())
            chain.append(hash_obj.hexdigest())
        return chain

    def generate_hash_element(self, seed, index):
        element = seed
        for _ in range(index):
            hash_obj = SHA256.new(element.encode())
            element = hash_obj.hexdigest()
        return element

    def encrypt_data(self, data):
        cipher = PKCS1_OAEP.new(self.public_key)
        return cipher.encrypt(data.encode()).hex()

    def decrypt_data(self, data):
        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted = cipher.decrypt(bytes.fromhex(data)).decode()
        return decrypted
