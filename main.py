import Crypto

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5

class Module(object):
    def __init__(self):
        pass

    def handle_message(self,message:bytearray):
        pass

    def finish(self):
        pass


class Authenticator(Module):
    def __init__(self):
        super().__init__(self)

test_key = RSA.generate(2048)
test_message = bytes("I'm encrypted!",'utf-8')
cipher = PKCS1_OAEP.new(test_key)
encrypted_message = cipher.encrypt(test_message)
print(PKCS1_v1_5.new(test_key.publickey()).verify(encrypted_message))
dec_cipher = PKCS1_OAEP.new(test_key.publickey())
dec_message = dec_cipher.decrypt(encrypted_message)

print(encrypted_message)
print(dec_message)
