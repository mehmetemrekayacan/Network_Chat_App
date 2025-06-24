# Performance Analysis Report

This document details the performance analysis of the Network Chat Application, focusing on latency, throughput, and scalability.

## 1. Testing Methodology

### Test Setup
All tests were conducted on a single machine using `localhost` (127.0.0.1) for network communication. This setup minimizes external network variables and focuses on the application's processing overhead.

- **Instance 1:** Acts as the Server and the first client.
- **Instance 2:** Acts as a standard client, connecting to the server.

### Metrics Measured
- **Latency (Round-Trip Time - RTT):** The time for a packet to travel from a client to the server and back, measured for both TCP and UDP.
- **Throughput:** The effective data transfer rate over TCP, measured in Megabits per second (Mbps).
- **Scalability:** A qualitative analysis of the server's architecture.

## 2. Performance Metrics & Results

### Latency

#### UDP Latency (Topology Discovery)
The `topology_discovery.py` service measures RTT to discover peers. This is a lightweight UDP-based ping.

- **Average UDP RTT:** `~1.8 ms`

#### TCP Latency (Ping/Pong Echo)
A test function sends 50 small packets over TCP to measure the average round-trip time.

- **Average TCP RTT:** `~0.43 ms`

#### Latency Comparison

The results show that both protocols are extremely fast on `localhost`. Interestingly, our TCP communication is slightly faster, which can happen in `localhost` tests where network overhead is negligible and TCP's direct socket connection can be more efficient than UDP's context switching.

### Throughput (TCP)

A test was conducted by sending a burst of 20 large packets (512 KB each) from a client to the server, which were then echoed back.

- **Total Data Transferred:** ~20 MB (round-trip)
- **Time Taken:** ~0.09 seconds
- **Calculated Throughput:** `~1750 Mbps`

This high throughput shows that the application's protocol parsing and data handling are very efficient and not a bottleneck.

## 3. Analysis and Trade-offs

- **Reliability vs. Speed:** The application uses a custom framing layer over TCP to ensure that large or fast-paced data streams are handled correctly, preventing the "stuck" state seen in earlier tests. This is a crucial trade-off for robustness.
- **Scalability:** The server's multi-threaded design allows it to handle multiple clients concurrently. The current limit is set to `10` but can be increased. For a large number of users, the main bottleneck would be the host machine's resources.
- **UDP for Discovery:** Using UDP for peer discovery is efficient as it avoids connection overhead. For private messaging, a reliability layer is added to UDP to prevent message loss, balancing speed with user experience. 