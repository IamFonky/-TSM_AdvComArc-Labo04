import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Fonction fn
def fn(*args):
    hmac_i = b''
    for arg in args:
        hmac_i += bytes.fromhex(arg)
    return hashlib.sha1(hmac_i).hexdigest()

# Fonction f1
def f1(*args):
    return fn(*args)

# Fonction f2
def f2(k, rand):
    return fn(k, rand)[0:8]

# Fonction f3
def f3(k, rand):
    return fn(k, rand)[8:16]


# Fonction f4
def f4(k, rand):
    return fn(k, rand)[16:24]

# Fonction f5
def f5(k, rand):
    return fn(k, rand)[24:32]

def f8(ck, frame, direction, length):
    # Convertir les paramètres en bytes
    ck = bytes.fromhex(ck)
    frame = bytes.fromhex(frame)
    direction = bytes.fromhex(direction)

    # Générer la clé de chiffrement
    key = ck + b'\x00' * 11 + direction

    # Initialiser le compteur
    count = int.from_bytes(frame, byteorder='big')

    # Générer le keystream
    keystream = b''
    for i in range(length):
        aes = AES.new(key, AES.MODE_ECB)
        block = count.to_bytes(16, byteorder='big')
        keystream += aes.encrypt(block)[-1:]
        count += 1

    # Retourner le keystream
    return keystream.hex()

def f9(ik, rand):
    # Convertir les paramètres en bytes
    ik = bytes.fromhex(ik)
    rand = bytes.fromhex(rand)

    # Générer la clé d'intégrité
    key = ik + b'\x00' * 12

    # Initialiser le compteur
    count = b'\x00' * 16

    # Générer l'authentificateur
    length = len(rand).to_bytes(2, byteorder='big')
    data = rand + length + b'\x00' * 2
    padding = pad(data, AES.block_size)
    aes = AES.new(key, AES.MODE_CBC, count)
    auth = aes.encrypt(padding)[-4:]

    # Retourner l'authentificateur
    return auth.hex()