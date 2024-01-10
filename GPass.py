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

def decifrar_dados_ofuscados(info_ofuscada, passphrase):
    # Extrair o salt e IV
    salt = info_ofuscada['salt']
    iv = info_ofuscada['iv']

    # Derivar a chave a partir do passphrase, salt e IV
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    chave = kdf.derive(passphrase.encode('utf-8'))

    # Descriptografar 'ip'
    cipher_ip = Cipher(algorithms.AES(chave), modes.CFB(iv), backend=default_backend())
    decryptor_ip = cipher_ip.decryptor()
    ip_base64 = decryptor_ip.update(info_ofuscada['IP']) + decryptor_ip.finalize()
    ip_original = base64.b64decode(ip_base64).decode('utf-8')

    # Descriptografar 'login'
    cipher_login = Cipher(algorithms.AES(chave), modes.CFB(iv), backend=default_backend())
    decryptor_login = cipher_login.decryptor()
    login_base64 = decryptor_login.update(info_ofuscada['L']) + decryptor_login.finalize()
    login_original = base64.b64decode(login_base64).decode('utf-8')

    # Descriptografar 'senha'
    cipher_senha = Cipher(algorithms.AES(chave), modes.CFB(iv), backend=default_backend())
    decryptor_senha = cipher_senha.decryptor()
    senha_base64 = decryptor_senha.update(info_ofuscada['P']) + decryptor_senha.finalize()
    senha_original = base64.b64decode(senha_base64).decode('utf-8')

    return {'IP': ip_original, 'L': login_original, 'P': senha_original}

def recuperar_senhas(arquivo_ofuscado, passphrase):
    with open(arquivo_ofuscado, 'rb') as f_ofuscado:
        senhas_ofuscadas = pickle.load(f_ofuscado)

    for id, senha_ofuscada in senhas_ofuscadas.items():
        dados_original = decifrar_dados_ofuscados(senha_ofuscada, passphrase)
        print(f"{id} {dados_original['IP']}   {dados_original['L']}     {dados_original['P']}")

if __name__ == "__main__":
    arquivo_ofuscado = "sicdc.bin"

    # export PASSPHRASE="Cnpa2024#"
    passphrase = os.getenv("PASSPHRASE")

    if passphrase is None:
        print("Erro: A variável de ambiente não está configurada.")
    else:
        print("        IP      Login        Senha")
        recuperar_senhas(arquivo_ofuscado, passphrase)
