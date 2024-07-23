Overview

This project involves the development of a secure distributed application using Java and Java's security API. The project is divided into two phases, each focusing on different aspects of the system: initial functionality and subsequent security enhancements.
Phase 1: Functional Implementation
Objectives

The primary goal of the first phase was to create a functional distributed application, simulating an Internet of Things (IoT) environment with a client-server architecture. The main functionalities implemented are:

    IoTDevice: A client application that simulates a sensing device, capable of sending sensory data (images and temperature values) to a server and accessing data from the server.
    IoTServer: A server application that manages multiple client connections, authenticates users, stores data from clients, and organizes and shares this data in a persistent manner.

System Architecture

The system consists of:

    IoTDevice: Represents a sensor device, responsible for sending data to the server and accessing data.
    IoTServer: Manages connections, maintains information about devices, domains, and users, and authenticates and shares data received from clients.

Phase 2: Security Enhancements
Objectives

In the second phase, the focus shifts to incorporating security features to ensure secure interactions and system integrity. The functionalities from the first phase remain unchanged but are adapted to meet security requirements.
Security Features Implemented

    TLS Secure Communication:
        All communications between clients and the server are secured using TLS, ensuring confidentiality and authenticity.
        Each client and the server use keystores for storing private keys and truststores for storing public key certificates.

    Encryption and Key Management:
        Private keys are stored in password-protected keystores.
        Public key certificates are stored in a truststore accessible to all clients.
        User data on the server is encrypted using a symmetric key derived from a password using PBE (Password-Based Encryption) with AES 128-bit.

    End-to-End Data Confidentiality:
        Data shared within a domain is encrypted with a domain-specific key, ensuring only authorized users in the same domain can decrypt it.

    Two-Factor Authentication (2FA):
        Users authenticate using asymmetric cryptography and a code sent via email.
        This ensures that only legitimate users with access to their private keys and email can authenticate.

    Remote Attestation:
        Clients prove their integrity by sending a hash of their executable combined with a nonce, preventing replay attacks.
How to Run

Please refer to the detailed README inside the project folder for instructions on how to run the project.
        
