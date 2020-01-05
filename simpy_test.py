import random
import struct

import simpy
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
import json
import pickle


class network_module(object):
    def __init__(self,env:simpy.Environment,name="unnamed"):
        self.env = env
        self.pending_messages = []
        self.name = name

    def on_start(self):
        pass

    def run(self):
        self.on_start()
        while True:
            if self.has_message():
                self.handle_message(self.get_message())
            yield self.env.timeout(0.05)

    def has_message(self):
        return len(self.pending_messages) > 0

    def get_message(self):
        return self.pending_messages.pop()

    def handle_message(self,message:bytearray):
        pass

    def send(self,message:bytes,recieve_buffer:list):
        # yield self.env.timeout(0.05)
        print('Time: ',self.env.now,', Name: ',self.name,', Sending Encrypted Message:',message[0:4],'...')
        recieve_buffer.append(message)

    def encrypt_all_bytes(self,unencrypted_bytes,cipher):
        ret = bytes()
        for i in range(0,len(unencrypted_bytes),214):
            ret += cipher.encrypt(unencrypted_bytes[i:i+214])
        return ret

    def decrypt_all_bytes(self,encrypted_bytes,cipher):
        ret = bytes()
        for i in range(0,len(encrypted_bytes),256):
            ret += cipher.decrypt(encrypted_bytes[i:i+256])
        return ret

    def create_encrypted_message(self,message_dict,sign_cipher,encrypt_cipher):
        hash = SHA256.new()
        hash.update(bytearray(struct.pack('f',message_dict['time'])))
        message_dict['signature'] = sign_cipher.sign(hash)
        unencrypted_message_bytes = pickle.dumps(message_dict)
        encrypted_message_bytes = self.encrypt_all_bytes(unencrypted_message_bytes,encrypt_cipher)
        return encrypted_message_bytes

    def decrypt_message(self,encrypted_message_bytes,decrypt_cipher):
        decrypted_message = self.decrypt_all_bytes(encrypted_message_bytes, decrypt_cipher)
        return pickle.loads(decrypted_message)

    def verify_signature(self,signature,verify_cipher,target):
        hash = SHA256.new()
        hash.update(bytearray(struct.pack('f',target)))
        return verify_cipher.verify(hash,signature)

class authenticator(network_module):
    def __init__(self,env:simpy.Environment):
        super().__init__(env,'authenticator')
        self.pacemaker_buffer = None
        self.pacemaker_public_key = None
        self.private_key = RSA.generate(2048)

    def set_pacemaker(self,pacemaker:network_module):
        self.pacemaker_buffer = pacemaker.pending_messages
        pacemaker.auth_public_key = self.private_key.publickey()

    def handle_message(self,message:bytearray):
        message_dict = self.parse_message(message)
        print('Time: ',self.env.now,', Name: ',self.name,', Recieved Message: ',message_dict['type'])
        if message_dict['type'] == 'error':
            return
        elif message_dict['type'] == 'auth_request':
            self.send(self.create_authentication_response_message(),self.pacemaker_buffer)

    def parse_message(self,encrypted_message:bytearray):
        decrypt_cipher = PKCS1_OAEP.new(self.private_key)
        message_dict = self.decrypt_message(encrypted_message,decrypt_cipher)
        if message_dict['type'] == 'auth_request':
            verify_cipher = PKCS1_v1_5.new(self.pacemaker_public_key)
        else:
            return {'type':'error'}

        if self.verify_signature(message_dict['signature'],verify_cipher,message_dict['time']):
            return message_dict
        else:
            return {'type':'error'}

    def create_authentication_response_message(self):
        message_dict = {'type':'auth_response','time':self.env.now}
        sign_cipher = PKCS1_v1_5.new(self.private_key)
        encrypt_cipher = PKCS1_OAEP.new(self.pacemaker_public_key)
        return self.create_encrypted_message(message_dict,sign_cipher,encrypt_cipher)

class pacemaker(network_module):
    def __init__(self,env:simpy.Environment):
        super().__init__(env,"pacemaker")
        self.private_key = RSA.generate(2048)
        self.auth_buffer = None
        self.auth_public_key = None
        self.programmer_buffer = None
        self.programmer_public_key = None

    def handle_message(self,message:bytearray):
        message_dict = self.parse_message(message)
        print('Time: ',self.env.now,', Name: ',self.name,', Recieved Message: ',message_dict['type'])
        if message_dict['type'] == 'error':
            return
        elif message_dict['type'] == 'op_request':
            self.send(self.create_auth_request_message(),self.auth_buffer)
        elif message_dict['type'] == 'auth_response':
            self.send(self.create_op_response_message(),self.programmer_buffer)

    def set_backend(self,backend):
        backend.pacemaker_public_key = self.private_key.publickey()

    def set_programmer(self,programmer:network_module):
        self.programmer_buffer = programmer.pending_messages
        programmer.pacemaker_public_key = self.private_key.publickey()

    def set_authenticator(self,authenticator:authenticator):
        self.auth_buffer = authenticator.pending_messages
        authenticator.pacemaker_public_key = self.private_key.publickey()

    def parse_message(self,encrypted_message:bytearray):
        decrypt_cipher = PKCS1_OAEP.new(self.private_key)
        message_dict = self.decrypt_message(encrypted_message,decrypt_cipher)
        if message_dict['type'] == 'op_request':
            verify_cipher = PKCS1_v1_5.new(self.programmer_public_key)
        elif message_dict['type'] == 'auth_response':
            verify_cipher = PKCS1_v1_5.new(self.auth_public_key)
        else:
            return {'type':'error'}

        if self.verify_signature(message_dict['signature'],verify_cipher,message_dict['time']):
            return message_dict
        else:
            return {'type':'error'}

    def create_auth_request_message(self):
        # challenge = bytearray([random.randint(0,255) for i in range(8)])
        time = self.env.now
        message_dict = {'type':'auth_request','time':time}
        sign_cipher = PKCS1_v1_5.new(self.private_key)
        encrypt_cipher = PKCS1_OAEP.new(self.auth_public_key)
        return self.create_encrypted_message(message_dict,sign_cipher,encrypt_cipher)

    def create_op_response_message(self):
        time = self.env.now
        message_dict = {'type':'op_response','time':time}
        sign_cipher = PKCS1_v1_5.new(self.private_key)
        encrypt_cipher = PKCS1_OAEP.new(self.programmer_public_key)
        return self.create_encrypted_message(message_dict,sign_cipher,encrypt_cipher)

class programmer(network_module):
    def __init__(self,env:simpy.Environment,test_mode="Standard OP"):
        super().__init__(env,"programmer")
        self.pacemaker_buffer = None
        self.pacemaker_public_key = None
        self.backend_buffer = None
        self.backend_public_key = None
        self.test_mode = test_mode
        self.private_key = RSA.generate(2048)

    def set_pacemaker(self,pacemaker:pacemaker):
        self.pacemaker_buffer = pacemaker.pending_messages
        pacemaker.programmer_public_key = self.private_key.publickey()

    def set_backend(self,backend:network_module):
        self.backend_buffer = backend.pending_messages


    def on_start(self):
        if self.test_mode == "Standard OP":
            self.send(self.create_op_request_message(),self.pacemaker_buffer)

    def create_op_request_message(self):
        message_dict = {'type':'op_request','time':self.env.now}
        return self.create_encrypted_message(message_dict,PKCS1_v1_5.new(self.private_key),PKCS1_OAEP.new(self.pacemaker_public_key))

    def handle_message(self,message:bytearray):
        decrypt_cipher = PKCS1_OAEP.new(self.private_key)
        message_dict = self.decrypt_message(message,decrypt_cipher)
        print('Time: ',self.env.now,', Name: ',self.name,', Recieved Message: ',message_dict['type'])
        if message_dict['type'] == 'error':
            return
        elif message_dict['type'] == 'op_response':
            verify_cipher = PKCS1_v1_5.new(self.pacemaker_public_key)

        if self.verify_signature(message_dict['signature'],verify_cipher,message_dict['time']):
            if message_dict['type'] == 'op_response':
                self.send(self.forward_op_response(message_dict), self.backend_buffer)

    def forward_op_response(self,message_dict):
        encrypt_cipher = PKCS1_OAEP.new(self.backend_public_key)
        unencrypted_message_bytes = pickle.dumps(message_dict)
        return self.encrypt_all_bytes(unencrypted_message_bytes,encrypt_cipher)





class backend(network_module):
    def __init__(self,env:simpy.Environment):
        super().__init__(env,"backend")
        self.programmer_buffer = None
        self.programmer_public_key = None
        self.pacemaker_public_key = None
        self.private_key = RSA.generate(2048)


    def set_programmer(self,programmer:programmer):
        self.programmer_buffer = programmer.pending_messages
        programmer.backend_public_key = self.private_key.publickey()


    def handle_message(self,message:bytearray):
        decrypt_cipher = PKCS1_OAEP.new(self.private_key)
        message_dict = self.decrypt_message(message,decrypt_cipher)
        if message_dict['type'] == 'error':
            return
        elif message_dict['type'] == 'op_response':
            verify_cipher = PKCS1_v1_5.new(self.pacemaker_public_key)

        if self.verify_signature(message_dict['signature'],verify_cipher,message_dict['time']):
            print('Time: ',self.env.now,', Name: ',self.name,', Recieved Message: ',message_dict['type'])


env = simpy.Environment()
# n1 = tic(env)
# n2 = toc(env)
# n1.set_toc(n2)
# n2.set_tic(n1)
# env.process(n1.run())
# env.process(n2.run())
pm = pacemaker(env)
prg = programmer(env)
auth = authenticator(env)
back = backend(env)

auth.set_pacemaker(pm)
prg.set_pacemaker(pm)
prg.set_backend(back)
pm.set_authenticator(auth)
pm.set_programmer(prg)
pm.set_backend(back)
back.set_programmer(prg)

env.process(back.run())
env.process(auth.run())
env.process(pm.run())
env.process(prg.run())



env.run(until=0.5)
# env.run(until=10)
