import socket
import select
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Create the client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Function to load the public key (server's public key)
def load_public_key():
    with open("public.pem", "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    return public_key

# Function to load the private key (client's private key)
def load_private_key():
    with open("private.pem", "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    return private_key

# Encrypt a message using the public key
def encrypt_message(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return encrypted_message

# Decrypt a message using the private key
def decrypt_message(private_key, encrypted_message):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
    return decrypted_message

# Check if correct arguments are provided
if len(sys.argv) != 3:
    print("Correct usage: script, IP address, port number")
    exit()

IP_address = str(sys.argv[1])
Port = int(sys.argv[2])

client.connect((IP_address, Port))

private_key = load_private_key()  # Load the client's private key
public_key = load_public_key()    # Load the server's public key

def close_client():
    """Close the client connection."""
    print("Disconnecting...")
    client.close()
    sys.exit(0)

try:
    while True:
        sockets_list = [sys.stdin, client]
        read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])

        for socks in read_sockets:
            if socks == client:
                encrypted_message = socks.recv(2048)
                if encrypted_message:
                    decrypted_message = decrypt_message(private_key, bytes.fromhex(encrypted_message.decode()))
                    print(decrypted_message)
            else:
                message = input()
                if message.strip().lower() == "exit":
                    close_client()  # Gracefully close the client
                if message.strip():
                    encrypted_message = encrypt_message(public_key, message)  # Encrypt message before sending
                    client.send(encrypted_message.hex().encode())
                    print(f"<You> {message}")
except KeyboardInterrupt:
    print("\nInterrupted. Exiting...")
    close_client()  # Ensure client disconnects on Ctrl+C
