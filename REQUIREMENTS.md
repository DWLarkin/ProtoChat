# Client

## Overview
These are clients which users will interact with in order to connect to dedicated servers, as well as interact with other users. It displays status messages, accepts commands, sends messages from the current user, and displays messages sent from other users as well.

## Basic Requirements
- Written in C (this is more for demonstration purposes, preferably this would use a different language on final version.)
- Ability to send messages with standard Unicode content (symbols, emojis, etc.)
    - Should also receive and display these as expected.
- Notifications to all connected users when a new user connects, or a current one disconnects.
- Anonymous, ephemeral connections; will prompt a user for a display name upon launch and send that over the wire.
- Support a few basic commands.
- Print messages/output directly to terminal.

## Extended Requirements
- Make it look purdy using ncurses.
    - Add async to client and remove /refresh.
- Ability to upload files to and download from the server.
- Support various commands, both fun and administrative (/confetti, /kick, /files, etc.)
- Secure communications with either TLS or QUIC.
- Support Signal protocol for user-to-user encrypted comms.
- Persistent users and credentialing.
    - This should also open an avenue for admin accounts.
    - Would probably look like a standard hashed password comparison

# Server

## Overview
This would be a dedicated async server that serves as a middleman between all communications. The basic requirement implementation would have nothing persistent, so user connections would be ephemeral and anonymous other than required connection info and the username that's passed in. If fully extended, should have secure and persistent configurations for both the current runtime as well as active clients.

## Basic Requirements
- Written in Python.
- Written asynchronously.
    - Meaning there should never be any busy waiting or lengthy blocking that could potentially prevent it from handling other activities (this includes file streaming).
    - Incoming commands/messages will probably get thrown onto a queue or similar mechanism, and track which users that task still needs to send information to. Probably attempt to send to one client at a time when we pop write ready.
- Incoming messages from one client should be broadcast to all others.
- Basic server configuration available via arguments.

## Extended Requirements
- Once uploaded, files should be stored on the server's local filesystem for later client downloading.
- Persistent user authentication.
- TLS/QUIC connections.
- Support for Signal protocol.
- Secure storage of both files and credentials.
    - Secure file storage is gonna be interesting. Might be able to store the key encrypted via Signal and have it decrypted on the client side, hard to say without knowing more about how those libraries work.
- Server configuration editing via CLI.

# Testing

Probably will not get around to this with how little time I have.
- Would be nice to have some good C unit testing via GoogleTest to make sure a lot of the isolated logic works reliably.
- Functional/integration testing using PyTest, where we could spin up + interact with both clients and servers via a handy API.
- Also not really testing, but would be nice to run stuff through a pipeline, linters, etc.
