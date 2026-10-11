# AuthModbus

This repository contains all the software artifacts for the AuthModbus protocol submitted to ISGT 2026 conference. 
In addition to source code, I uploaded the binaries that are tested on Ubuntu 24.04 LTS.

# Paper Abstract
Modbus/TCP remains one of the most widely deployed communication protocols in industrial control systems, yet it lacks native mechanisms for authentication, integrity, and replay protection. Existing solutions, such as Modbus/TLS, provide strong cryptographic guarantees but often introduce deployment complexity, are too expensive, and have higher computational overhead, which limits their practicality in legacy or resource-constrained industrial environments. Furthermore, in many operational settings, preventing unauthorized commands and message manipulation is more critical than protecting the confidentiality of process data. This paper presents Auth-Modbus, a lightweight applicationlayer security extension for Modbus/TCP that provides authentication, message integrity, replay protection, and session binding without requiring transport-layer encryption. In particular, AuthModbus establishes a session-based, authenticated channel using a pre-shared key (i.e., a long-term key) and protects subsequent Modbus messages with message authentication codes. We then implement a prototype using libmodbus and OpenSSL without modifying existing Modbus stacks. Moreover, our experimental results show that Auth-Modbus not only strengthens Modbus/TCP security but also achieves 31.94% less latency and 46.90% higher throughput than the baseline libmodbus implementation, and it is faster than other Modbus implementations. This demonstrates that practical security enhancements for legacy industrial protocols can be achieved without sacrificing runtime performance.

# Client Benign Read
The operator connects and queries the Modbus values from the server.

![Image](/images/client_read.png)

# Client Benign Write
The operator connects and overwrite the Modbus values from the server. For example, a PLC measures the wind speed value and overwrites the corresponding Modbus register accordingly.

![Image](/images/client_write.png)

# Attacks Failed
The proposed Modbus server solution is resillient against invalid HMAC after authentication, replayed authenticated request, tampered Modbus payload, unauthenticated write attempt, and forged session identifier attacks.

![Image](/images/attacks_failed.png)

# Performance Metrics

### AuthModbus
![Image](/images/auth_modbus_statistics.png)

### Libmodbus
![Image](/images/libmodbus_statistics.png)

### Pymodbus
![Image](/images/pymodbus_statistics.png)

### Pymodbus/TLS
![Image](/images/pymodbus_tls_statistics.png)
