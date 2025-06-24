# Network Chat Application Project

## Description

This project is a multi-user chat application built for the Networking Course. It implements all core components of Option 1, including a custom protocol, public chat over TCP, reliable private messaging over UDP, and a network topology discovery service. The application features a modern, responsive graphical user interface.

It supports:
- **Dual Protocol Communication:** Uses TCP for reliable public chat and UDP for low-latency private messaging and peer discovery.
- **Graphical User Interface:** A user-friendly GUI built with customtkinter.
- **Network Topology Discovery:** Automatically discovers other users on the local network and displays them, along with Round-Trip Time (RTT) measurements.
- **Reliable UDP:** Implements a custom reliability layer on top of UDP with sequence numbers and acknowledgments to prevent message loss.
- **Performance Testing:** Includes built-in tools to measure TCP latency (RTT) and throughput directly from the UI.

## Team Members

- Mehmet Emre Kayacan
- Oğuz Genç
- Muhammed Enes Çetinkaya

## Dependencies

All required Python libraries are listed in the `requirements.txt` file.

## Installation and Running Instructions

These instructions will guide you through setting up and running the application.

1.  **Unzip the Archive:**
    Extract the contents of the `.zip` file into a folder on your computer.

2.  **Create a Virtual Environment (Recommended):**
    Open a terminal in the project folder and run the following commands:
    ```bash
    # Create the virtual environment
    python -m venv venv

    # Activate the environment
    # On Windows:
    .\venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    With the virtual environment active, install the required libraries using the provided file:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the Application:**

    This application requires a dedicated server to be running before clients can connect.

    **A. Start the Server:**
    - Open your terminal or command prompt.
    - Navigate to the project directory.
    - Run the `start_server.py` script. This will launch the TCP and UDP servers.
    ```sh
    python start_server.py
    ```
    - The server will remain running in this terminal window.

    **B. Start the Client(s):**
    - Open a **new** terminal for each client you want to run.
    - Navigate to the project directory.
    - Run the `chat_gui.py` file using Python.
    ```sh
    python chat_gui.py
    ```
    - The application window will open. You can launch multiple clients this way.

## How to Use
1.  On each client window, **enter a unique username** in the "Username" field.
2.  Click **"🚀 Connect"**.
    - This will connect the client to the dedicated server.
3.  You can now chat in the public room, or select users for private messaging. 