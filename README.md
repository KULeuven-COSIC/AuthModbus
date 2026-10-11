# AuthModbus

This repository contains all the software artifacts for the AuthModbus protocol submitted to ISGT 2026 conference. 
In addition to source code, I uploaded the binaries that are tested on Ubuntu 24.04 LTS.

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
