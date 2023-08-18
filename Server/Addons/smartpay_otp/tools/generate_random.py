import secrets
import string


def generate_secrets_code(length=32, choices='', generate_type=''):
    """Generate random secrets code
    @param length: length of secrets
    @param choices: list of secrets to generate
    @param generate_type: type of secret code to generate based on type

    @return: generate random secure code"""
    generateSecrets = secrets.SystemRandom()
    if generate_type == 'valid_code':
        choices = choices or string.ascii_letters + string.digits
    elif generate_type == 'otp_code':
        choices = choices or string.digits
    elif generate_type == 'secrete_code':
        choices = choices or string.ascii_letters + string.digits
    else:
        choices = string.ascii_letters + string.digits

    return ''.join(generateSecrets.choices(choices)[0] for i in range(length))
