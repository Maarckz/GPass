import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import pickle

def criar_hash_ofuscada(info, passphrase):
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    chave = kdf.derive(passphrase.encode('utf-8'))

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(chave), modes.CFB(iv), backend=default_backend())

    ip_base64 = base64.b64encode(info['IP'].encode('utf-8')).decode('utf-8')
    encryptor_ip = cipher.encryptor()
    ip_ofuscado = encryptor_ip.update(ip_base64.encode('utf-8')) + encryptor_ip.finalize()

    login_base64 = base64.b64encode(info['L'].encode('utf-8')).decode('utf-8')
    encryptor_login = cipher.encryptor()
    login_ofuscado = encryptor_login.update(login_base64.encode('utf-8')) + encryptor_login.finalize()

    senha_base64 = base64.b64encode(info['P'].encode('utf-8')).decode('utf-8')
    encryptor_senha = cipher.encryptor()
    senha_ofuscada = encryptor_senha.update(senha_base64.encode('utf-8')) + encryptor_senha.finalize()

    return {'IP': ip_ofuscado, 'L': login_ofuscado, 'P': senha_ofuscada, 'salt': salt, 'iv': iv}

def criar_arquivo_ofuscado(dados, arquivo_ofuscado, passphrase):
    dados_ofuscados = {id: criar_hash_ofuscada(info, passphrase) for id, info in dados.items()}

    with open(arquivo_ofuscado, 'wb') as f_ofuscado:
        pickle.dump(dados_ofuscados, f_ofuscado)

    print(f"Todos os dados ofuscados e salvos em {arquivo_ofuscado}")


if __name__ == "__main__":
    dados_senhas = {
        1: {'IP': '192.168.0.1', 'L': 'usuario1', 'P': 'teste', '': ''},
        2: {'IP': '192.168.0.1', 'L': 'usuario1', 'P': 'teste', '': ''},
        3: {'IP': '192.168.0.1', 'L': 'usuario1', 'P': 'teste', '': ''},
    }

    arquivo_ofuscado = "sicdc.bin"
    passphrase = "Cnpa2024#"

    criar_arquivo_ofuscado(dados_senhas, arquivo_ofuscado, passphrase)
