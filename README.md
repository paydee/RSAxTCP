# RSAxTCP

**Simple implementation of TCP protocol using RSA for encrypt/decrypt the message**

## Protocol

Each program, client or server, does the following work:

- Creation of the RSA key pair;

- Once the TCP connection is established, the client and the server exchange their value 𝑛 since 𝑒 is known;
vs. he can exchange encrypted data with his companion
- A sequence of characters read on the keyboard, then encrypted by 𝑒 and 𝑛 of his companion;
- A sequence of values read from the TCP connection and decrypted by its own parameters 𝑑 and 𝑛.

The values exchanged will be organized in the form of lines of text sent and received through
the TCP connection, in a format that you will establish yourself.
