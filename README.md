# ProtoChat

ProtoChat is a basic TUI chat program, intended to demonstrate design and networking concepts.

## Building

### Requirements

- CMake
- Python
- Linux-based environment

### Client

1. Navigate to the client directory in your shell of choice.
2. `cmake -S . -B build` sets up the CMake build folder.
3. `cmake --build build` builds the client.
4. `./build/client` will launch the client.

### Server

1. Server can be launched directly or via Python (assuming the execute bit remains flipped on clone). I.E. `python3 ./server/protoserver.py` vs `./server/protoserver.py`
2. The server accepts two optional arguments and a positional argument, in the style of `protoserver.py [-a ADDRESS] [-p PORT] groupname`.
    - Note that the address and port arguments default to `0.0.0.0:1337`.
3. More information about these arguments can be learned by running it with the `-h` argument.

## Usage

1. Launch a server with a valid group name, and optionally an address and port. I.E. `./server/protoserver.py "cool group"`
2. Launch a client and go through setup, putting in an address (or domain) and port that correspond to a valid server.
3. Provide the client with a valid user name to provide upon entering the chat.
4. You're in!
