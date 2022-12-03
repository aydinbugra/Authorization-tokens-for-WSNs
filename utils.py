def get_secret_key(): # For role based authorization, each role can be used different secret keys 
    with open('secret.key', 'r') as key_file:
        return key_file.read()