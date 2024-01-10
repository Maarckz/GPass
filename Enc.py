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

    # Codificar dados em Base64 antes de criptografar
    senha_base64 = base64.b64encode(info['senha'].encode('utf-8')).decode('utf-8')
    encryptor = cipher.encryptor()
    senha_ofuscada = encryptor.update(senha_base64.encode('utf-8')) + encryptor.finalize()

    return {'ip': info['ip'], 'login': info['login'], 'senha': senha_ofuscada, 'salt': salt, 'iv': iv}

def criar_arquivo_ofuscado(dados, arquivo_ofuscado, passphrase):
    dados_ofuscados = {id: criar_hash_ofuscada(info, passphrase) for id, info in dados.items()}

    with open(arquivo_ofuscado, 'wb') as f_ofuscado:
        pickle.dump(dados_ofuscados, f_ofuscado)

    print(f"Todos os dados ofuscados e salvos em {arquivo_ofuscado}")

if __name__ == "__main__":
    # Exemplo de variável com um dicionário de senhas
    dados_senhas = {
        1: {'ip': '192.168.0.1', 'login': 'usuario1', 'senha': 'teste', '': ''},
        2: {'ip': '192.168.0.1', 'login': 'usuario1', 'senha': 'teste', '': ''},
        3: {'ip': '192.168.0.1', 'login': 'usuario1', 'senha': 'teste', '': ''},
        # Adicione mais entradas conforme necessário
    }

    arquivo_ofuscado = "sicdc.bin"
    passphrase = "Cnpa2024#"

    criar_arquivo_ofuscado(dados_senhas, arquivo_ofuscado, passphrase)
