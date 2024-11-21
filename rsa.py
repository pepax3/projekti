from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA keys
def generate_rsa_keys():
    # Generate a new RSA key pair
    key = RSA.generate(2048)  # 2048 bits key length is common and secure enough for most uses
    private_key = key.export_key()  # Export the private key
    public_key = key.publickey().export_key()  # Export the public key
    return public_key, private_key

# Generate the keys
public_key, private_key = generate_rsa_keys()

# Save the keys to files
with open("public.pem", "wb") as pub_file:
    pub_file.write(public_key)

with open("private.pem", "wb") as priv_file:
    priv_file.write(private_key)

print("RSA keys generated and saved.")
