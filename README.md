# Network Chat Application

## 1. Team Members
- Mehmet Emre Kayacan
- Oğuz Genç
- Muhammed Enes Çetinkaya

## 2. Project Description
This project is a full-featured network chat application built with Python. It supports public chat rooms, private messaging, and peer-to-peer network discovery.

### Core Features:
- **Dual Protocol Communication:** Uses TCP for reliable public chat and UDP for low-latency private messaging and peer discovery.
- **Graphical User Interface:** A user-friendly GUI built with Tkinter allows for easy interaction.
- **Network Topology Discovery:** Automatically discovers other users on the local network and displays them, along with Round-Trip Time (RTT) measurements.
- **Reliable UDP:** Implements a custom reliability layer on top of UDP with sequence numbers and acknowledgments to prevent message loss.
- **Performance Testing:** Includes built-in tools to measure TCP latency (RTT) and throughput directly from the UI.

## 3. How to Run the Application

This application requires a dedicated server to be running before clients can connect.

### Prerequisites
- Python 3.x

### Running the Application
1.  **Start the Server:**
    - Open your terminal or command prompt.
    - Navigate to the project directory.
    - Run the `start_server.py` script. This will launch the TCP and UDP servers.
    ```sh
    python start_server.py
    ```
    - The server will remain running in this terminal window.

2.  **Start the Client(s):**
    - Open a **new** terminal for each client you want to run.
    - Navigate to the project directory.
    - Run the `chat_gui.py` file using Python.
    ```sh
    python chat_gui.py
    ```
    - The application window will open. You can launch multiple clients this way.

### How to Use
1.  On each client window, **enter a unique username** in the "Username" field.
2.  Click **"🚀 Connect"**.
    - This will connect the client to the dedicated server.
3.  You can now chat in the public room, or select users for private messaging. 