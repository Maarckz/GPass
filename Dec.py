import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import os
import pickle

def verificar_passphrase(input_passphrase, stored_passphrase_hash):
    input_passphrase_hash = hashlib.sha256(input_passphrase.encode('utf-8')).hexdigest()
    return input_passphrase_hash == stored_passphrase_hash

def decifrar_senha(senha_ofuscada, passphrase):
    # Extrair o salt e IV da senha ofuscada
    salt = senha_ofuscada['salt']
    iv = senha_ofuscada['iv']

    # Derivar a chave a partir do passphrase, salt e IV
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    chave = kdf.derive(passphrase.encode('utf-8'))

    # Descriptografar a senha com AES em modo CFB
    cipher = Cipher(algorithms.AES(chave), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    senha_base64 = decryptor.update(senha_ofuscada['senha']) + decryptor.finalize()

    # Decodificar Base64 para obter a senha original
    senha_original = base64.b64decode(senha_base64).decode('utf-8')

    return senha_original

def recuperar_senhas(arquivo_ofuscado, passphrase):
    with open(arquivo_ofuscado, 'rb') as f_ofuscado:
        senhas_ofuscadas = pickle.load(f_ofuscado)

    for id, senha_ofuscada in senhas_ofuscadas.items():
        senha_original = decifrar_senha(senha_ofuscada, passphrase)
        print(f"ID: {id}, IP: {senha_ofuscada['ip']}, Login: {senha_ofuscada['login']}, Senha original: {senha_original}")

if __name__ == "__main__":
    arquivo_ofuscado = "sicdc.bin"

    # export PASSPHRASE="Cnpa2024#"
    passphrase = os.getenv("PASSPHRASE")

    if passphrase is None:
        print("Erro: A variável de ambiente não está configurada.")
    else:
        recuperar_senhas(arquivo_ofuscado, passphrase)
