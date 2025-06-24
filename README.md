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

This application is built with Python's standard libraries, so no external packages are needed.

### Prerequisites
- Python 3.x

### Running the Application
1.  **Open your terminal or command prompt.**
2.  **Navigate to the project directory** where the files are located.
    ```sh
    cd path/to/your/project/folder
    ```
3.  **Run the `chat_gui.py` file** using Python.
    ```sh
    python chat_gui.py
    ```
4.  The application window will open. You can now start the server or connect to one.

### How to Use
1.  **Enter a username** in the "Username" field.
2.  Click **"🚀 Auto-Connect"**.
    - If no server is running on your local network, this instance will become the server.
    - If a server is already running, this instance will connect as a client.
3.  You can open multiple instances of the application to simulate a chat between different users on the same machine. 