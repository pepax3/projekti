import socket
import select
import sys
import threading  # Added for the console thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from _thread import start_new_thread

# Create the server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setblocking(False)  # Set non-blocking mode

# Function to load private key
def load_private_key():
    with open("private.pem", "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    return private_key

# Function to load public key
def load_public_key():
    with open("public.pem", "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    return public_key

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

# Bind the server
server.bind((IP_address, Port))
server.listen(100)

# List of connected clients
list_of_clients = []

# Shutdown flag
shutdown_flag = threading.Event()

# Start the server
def client_thread(conn, addr):
    private_key = load_private_key()  # Load the server's private key
    
    conn.send(encrypt_message(load_public_key(), "Welcome to the secure chatroom! Use exit command to disconnect from the server!").hex().encode())  # Send encrypted welcome message
    
    while not shutdown_flag.is_set():
        try:
            encrypted_message = conn.recv(2048)
            if encrypted_message:
                decrypted_message = decrypt_message(private_key, bytes.fromhex(encrypted_message.decode()))  # Decrypt the incoming message
                print(f"<{addr[0]}> {decrypted_message}")
                message_to_send = f"<{addr[0]}> {decrypted_message}"
                broadcast(message_to_send, conn)
            else:
                remove(conn)
                break
        except:
            continue

# Function to broadcast messages to all clients
def broadcast(message, connection):
    for clients in list_of_clients:
        if clients != connection:
            try:
                clients.send(encrypt_message(load_public_key(), message).hex().encode())  # Encrypt the message before sending
            except:
                clients.close()
                remove(clients)

# Function to remove a client
def remove(connection):
    if connection in list_of_clients:
        list_of_clients.remove(connection)

# Function to handle server console commands
def server_console():
    while not shutdown_flag.is_set():
        command = input()
        if command.strip().lower() == "exit":
            print("Shutting down the server...")
            shutdown_flag.set()
            # Close all client connections
            for client in list_of_clients:
                client.close()
            server.close()
            break

# Start the console thread
console_thread = threading.Thread(target=server_console, daemon=True)
console_thread.start()

# Main loop to accept connections
while not shutdown_flag.is_set():
    try:
        conn, addr = server.accept()
        list_of_clients.append(conn)
        print(f"{addr[0]} connected")
        start_new_thread(client_thread, (conn, addr))
    except BlockingIOError:
        # Non-blocking accept failed; continue to check the shutdown flag
        pass
    except Exception as e:
        print(f"Error: {e}")
        break

print("Server has been shut down.")
