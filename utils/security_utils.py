import bcrypt

def hash_password(password):
    """Gera um hash seguro para a senha."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(hashed_password, input_password):
    """Verifica se a senha fornecida corresponde ao hash."""
    return bcrypt.checkpw(input_password.encode('utf-8'), hashed_password.encode('utf-8'))