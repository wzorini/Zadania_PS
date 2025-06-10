from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from base64 import b64encode

key = input ('please insert your password: ')
key = key.encode('utf-8')
key = pad(key,AES.block_size)

def encrypt (file_name,key):
        with open(file_name,'rb') as entry:
            data = entry.read()
            cipher = AES.new(key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(data,AES.block_size))
            iv = b64encode(cipher.iv).decode('utf-8')
            ciphertext = b64encode(ciphertext).decode('utf-8')
            to_write = iv + ciphertext
        entry.close()
        with open('encrypted_'+ file_name,'w') as data:
            data.write(to_write)
        data.close()

encrypt('test.txt',key)