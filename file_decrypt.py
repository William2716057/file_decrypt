import getpass
import os
import struct
import sys
 
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 

MAGIC = b"PKENC1\n" #File signature writtent to encrypted file
#bitshift left
CHUNK = 1 << 20  # 1 MiB plaintext per chunk
#AES appends 16 byte tag to each chunk's ciphertext for tamper detection
TAG = 16
 
#build padding
def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)
 
#build the number used once
def chunk_nonce(prefix, index):
    return prefix + struct.pack(">I", index)
 

def load_private_key(path):
    with open(path, "rb") as f:
        data = f.read()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:  # if key is passphrase-protected
        pw = getpass.getpass("Private key passphrase: ").encode()
        return serialization.load_pem_private_key(data, password=pw)
 
 
def decrypt_file(priv_path, in_path, out_path):
    priv = load_private_key(priv_path)
    try:
        with open(in_path, "rb") as src, open(out_path, "wb") as dst:
            if src.read(len(MAGIC)) != MAGIC: #check header here
                sys.exit("File not produced by this tool.")
            (wlen,) = struct.unpack(">H", src.read(2))
            key = priv.decrypt(src.read(wlen), oaep())
            prefix = src.read(8)
            aes = AESGCM(key)
 
            index = 0
            cur = src.read(CHUNK + TAG)
            while True:
                nxt = src.read(CHUNK + TAG)
                last = not nxt
                dst.write(aes.decrypt(chunk_nonce(prefix, index), cur,
                                      b"\x01" if last else b"\x00"))
                if last:
                    break
                cur = nxt
                index += 1
    except BaseException:
        if os.path.exists(out_path):
            os.remove(out_path)  # Do not leave partial/unauthenticated output
        raise
 
 
if __name__ == "__main__":
    file_name = input("Enter encrypted file: ").strip().strip('"')
    private_key = input("Enter private key: ").strip().strip('"')
 
    if not os.path.isfile(file_name):
        sys.exit(f"File not found: {file_name}")
    if not os.path.isfile(private_key):
        sys.exit(f"Private key not found: {private_key}")
 
    if file_name.endswith(".enc"):
        out_name = file_name[:-4]
    else:
        out_name = file_name + ".dec"
 
    # Do not write over existing files.
    if os.path.exists(out_name):
        sys.exit(f"Will not write over existing file: {out_name}")
 
    try:
        decrypt_file(private_key, file_name, out_name)
    except Exception as e:
        sys.exit(f"Failed ({type(e).__name__}): wrong key, or the file has been corrupted.")
    print(f"Decrypted {file_name} as {out_name}")