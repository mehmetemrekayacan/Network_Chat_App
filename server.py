"""
Simple TCP Chat Server

This module implements a multi-threaded TCP server for a chat application.
It handles multiple client connections simultaneously, processes messages
according to the defined protocol, and broadcasts them to other clients.
It is designed to be integrated with a GUI, using a message queue to
communicate with the main application thread.
"""
import socket
import threading
import json
import time
import logging
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION,
    MAX_PACKET_SIZE, send_packet, receive_packet
)

# --- Globals ---
MAX_CLIENTS = 10  # Maximum number of concurrent clients allowed
clients = {}      # Dictionary to store connected clients -> {client_socket: (username, ip)}
lock = threading.Lock()  # A lock to ensure thread-safe access to the clients dictionary
server_socket = None     # The main server socket object
is_running = False       # A flag to control the main server loop

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def handle_client(client_socket, client_address):
    """
    Manages a single client connection in a dedicated thread.

    This function handles the initial "join" handshake, validates the new user,
    and then enters a loop to receive and process messages from the client.
    It handles normal messages and "leave" notifications.

    Args:
        client_socket (socket.socket): The socket object for the connected client.
        client_address (tuple): The client's address (ip, port).
    """
    logging.info(f"New connection from {client_address}")
    username = None
    try:
        # The first message from a client must be a "join" packet.
        join_data = receive_packet(client_socket)
        if not join_data:
            return  # Empty data means connection closed

        join_packet = parse_packet(join_data)
        if not join_packet or join_packet["header"]["type"] != "join":
            # If the packet is invalid or not a join packet, reject the connection.
            try:
                error_msg_packet = build_packet("SERVER", "message", "First message must be a valid JOIN packet.")
                send_packet(client_socket, error_msg_packet)
            except Exception:
                pass  # Ignore errors if the client has already disconnected
            return

        username = join_packet["header"]["sender"]

        with lock:
            # Check if the server is full
            if len(clients) >= MAX_CLIENTS:
                try:
                    full_msg_packet = build_packet("SERVER", "message", "Server is full.")
                    send_packet(client_socket, full_msg_packet)
                except Exception:
                    pass
                logging.warning(f"Connection from {client_address} rejected: Server full.")
                return

            # Check if the username is already taken
            if any(c[0] == username for c in clients.values()):
                try:
                    taken_msg_packet = build_packet("SERVER", "message", f"Username '{username}' is already in use.")
                    send_packet(client_socket, taken_msg_packet)
                except Exception:
                    pass
                logging.warning(f"Connection from {username}@{client_address} rejected: Username taken.")
                return

            # Add the new client to the dictionary
            clients[client_socket] = (username, client_address[0])

        # Announce the new user to the chat and send the updated user list.
        join_notification = f"{username} has joined the chat."
        broadcast(build_packet("SERVER", "message", join_notification), exclude=[client_socket])
        broadcast_user_list() # Send updated list to everyone
        logging.info(f"{username} joined from {client_address}")

        # Main loop to listen for messages from the client
        while is_running:
            try:
                raw_data = receive_packet(client_socket)
                if not raw_data:
                    break  # Empty data means the client disconnected gracefully

                packet = parse_packet(raw_data)
                if not packet:
                    continue  # Ignore invalid packets

                msg_type = packet["header"]["type"]
                sender = packet["header"]["sender"]
                
                if msg_type == "message":
                    text = packet["payload"]["text"]
                    # Broadcast the message to all OTHER clients
                    broadcast(build_packet(sender, "message", text), exclude=[client_socket])
                    logging.info(f"Broadcast message from {sender}")
                elif msg_type == "leave":
                    break  # Client has sent a leave notification
                elif msg_type == "ping":
                    # Respond to a ping with a pong, echoing the text for RTT measurement
                    text = packet["payload"]["text"]
                    pong_packet = build_packet("SERVER", "pong", text)
                    send_packet(client_socket, pong_packet)
                elif msg_type == "throughput_echo":
                    # Echo the packet back to the sender for throughput testing.
                    # Send the raw data back, but framed with our protocol.
                    send_packet(client_socket, raw_data)
                elif msg_type == "userlist_request":
                    broadcast_user_list(target_socket=client_socket)

            except (ConnectionResetError, ConnectionAbortedError):
                logging.warning(f"Client {username} disconnected unexpectedly.")
                break
            except Exception as e:
                logging.error(f"Error handling client {username}: {e}")
                break

    except Exception as e:
        # This catches errors during the initial handshake
        logging.error(f"Error with connection {client_address}: {e}")
    finally:
        # Cleanup: remove the client and notify others
        with lock:
            if client_socket in clients:
                # Ensure username was set before trying to use it
                if not username:
                    username = clients[client_socket][0]
                del clients[client_socket]

        client_socket.close()

        if username:
            leave_notification = f"{username} has left the chat."
            broadcast(build_packet("SERVER", "message", leave_notification))
            broadcast_user_list() # Send updated list to everyone
            logging.info(f"{username} disconnected.")
        else:
            logging.info(f"Connection terminated: {client_address}")


def broadcast(message: bytes, exclude: list = None):
    """
    Sends a message to all connected clients.

    Args:
        message (bytes): The message packet to be sent.
        exclude (list, optional): A list of client sockets to exclude from the broadcast.
                                  Defaults to None.
    """
    if exclude is None:
        exclude = []
    with lock:
        # Iterate over a copy of the keys, as the dictionary might be modified
        # if a client disconnects during the broadcast.
        for client in list(clients.keys()):
            if client in exclude:
                continue
            try:
                send_packet(client, message)
            except Exception:
                # If sending fails, the client might have disconnected.
                # The cleanup logic in handle_client will take care of removal.
                pass


def set_server_username(username: str):
    """
    Sets the username for the server host.
    This is no longer needed for a dedicated server.
    """
    pass


def broadcast_user_list(target_socket=None):
    """
    Builds and sends an updated user list to all connected clients,
    or to a specific client if target_socket is provided.
    """
    with lock:
        # Get a list of usernames from connected clients
        all_users = [userinfo[0] for userinfo in clients.values()]

        # Build the userlist packet
        userlist_packet = build_packet(
            "SERVER", "userlist",
            f"Connected users: {', '.join(all_users)}",
            extra={"users": all_users}
        )
        
        if target_socket:
            # Send the list only to the requesting client
            try:
                send_packet(target_socket, userlist_packet)
            except Exception:
                # The cleanup logic in handle_client will take care of removal.
                pass
        else:
            # Send the list to every client
            for client in list(clients.keys()):
                try:
                    send_packet(client, userlist_packet)
                except Exception:
                    pass


def start_server_with_port(port=12345):
    """
    Starts the main TCP server loop.

    It binds to the specified port and listens for incoming connections,
    spawning a new thread for each accepted client.

    Args:
        port (int, optional): The port number to listen on. Defaults to 12345.
    """
    global server_socket, is_running

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set socket option to allow reusing the address, preventing "Address already in use" errors
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen()
        is_running = True
        logging.info(f"TCP Server started at 0.0.0.0:{port}")
        logging.info(f"Protocol v{PROTOCOL_VERSION}")
        logging.info(f"Max clients: {MAX_CLIENTS}")

        while is_running:
            try:
                # Use a timeout to allow the loop to check `is_running` flag periodically
                server_socket.settimeout(1.0)
                client_socket, client_address = server_socket.accept()
                thread = threading.Thread(target=handle_client,
                                       args=(client_socket, client_address))
                thread.daemon = True  # Ensures threads exit when the main program does
                thread.start()
            except socket.timeout:
                continue  # Go back to the start of the loop
            except Exception as e:
                if is_running:
                    logging.error(f"Error accepting connections: {e}")
                break

    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        stop_server(finally_call=True)


def start_server():
    """
    Starts the TCP server on the default port (12345).
    Maintained for backward compatibility.
    """
    start_server_with_port(12345)


def get_server_messages() -> list:
    """
    This is no longer needed for a dedicated server.
    """
    return []


def get_connected_users() -> list:
    """
    Retrieves the list of connected usernames for the GUI.

    This function is thread-safe.

    Returns:
        list: A list of usernames of the currently connected clients.
    """
    with lock:
        return [userinfo[0] for userinfo in clients.values()]


def stop_server(finally_call=False):
    """
    Safely shuts down the server.

    It notifies all clients, closes their connections, and then closes
    the main server socket.

    Args:
        finally_call (bool, optional): A flag to prevent duplicate "server stopped"
                                     messages when called from a finally block.
                                     Defaults to False.
    """
    global server_socket, is_running

    if not is_running:
        return  # Server is already stopped
    is_running = False

    # Notify all clients about the shutdown
    with lock:
        shutdown_msg = build_packet("SERVER", "message", "Server is shutting down...")
        for client in list(clients.keys()):
            try:
                send_packet(client, shutdown_msg)
                client.close()
            except Exception:
                pass
        clients.clear()

    # Close the main server socket
    if server_socket:
        try:
            server_socket.close()
        except Exception:
            pass
        server_socket = None

    if not finally_call:
        logging.info("TCP Server stopped.")


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
        stop_server()
