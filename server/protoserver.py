#!/usr/bin/env python3
"""Defines and potentially runs a ProtoChat server."""
import argparse
import socket

from dataclasses import field
from enum import IntEnum, auto


class NetworkConstants(IntEnum):
    MAX_SEND = 4096


class ProtocolCodes(IntEnum):
    INVALID_CODE = auto()
    CLIENT_HELLO = auto()
    SERVER_ACK = auto()
    OUT_OF_BOUNDS = auto()


def parse_proto_args() -> argparse.Namespace:
    """Parses the arguments for a ProtoChat server.

    Returns:
        An argparse namespace containing the arguments.

    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--address",
        type=validate_ip,
        required=True,
        default="0.0.0.0",
        help="The IPv4 or IPv6 address the server should on.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        required=True,
        default=1337,
        help="The port that the server should listen on.",
    )

    return parser.parse_args()


def validate_ip(str_input: str):
    """Validates a string representation of an IP.

    Args:
        str_input (str): The string to check.

    Raises:
        ValueError: If the string doesn't contain a valid address.

    """
    try:
        socket.inet_pton(socket.AF_INET, str_input)
        return str_input
    except OSError:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, str_input)
        return str_input
    except OSError:
        pass

    raise ValueError("Invalid address")


def check_address_family(str_addr: str) -> socket.AddressFamily:
    """Checks for the family of a stringified address.

    Args:
        str_addr (str): A string containing a valid IP address.

    Returns:
        Either socket.AF_INET or socket.AF_INET6.

    Raises:
        ValueError: If the string doesn't contain a valid address.

    """
    if "." in str_addr:
        return socket.AF_INET
    if ":" in str_addr:
        return socket.AF_INET6
    raise ValueError("String does not contain an address")


def recv_all(conn: socket.socket, data: bytes) -> bool:
    """Attempts to send all requested bytes.

    Args:
        conn (socket.socket): The socket to send on.
        len (int): The number of bytes to send.

    Returns:
        True if the bytes were sent, False on socket disconnect/failure.

    """
    while data:
        try:
            conn.sendall
        except OSError:
            return bytes()


class ProtoClient:
    """Class-based handler for ProtoChat clients."""

    def __init__(self, conn: socket.socket):
        self.conn = conn

    def close(self):
        self.conn.close()


class ProtoServer:
    """Class-based handler for server functionality."""

    def __init__(self, address: str, port: int):
        """Initialzes the ProtoChat server and starts the listening socket."""
        self.bind_address = address
        self.bind_port = port
        self.servsock: socket.socket | None = None
        self.clients: dict[str, ProtoClient] = field(default_factory=dict())

        self.start_listening()

    def start_listening(self):
        try:
            self.servsock = socket.create_server(
                (self.bind_address, self.bind_port),
                family=check_address_family(self.bind_address),
                reuse_port=True,
            )
            self.servsock.listen(5)
        except OSError as err:
            raise RuntimeError("failed to create ProtoChat server") from err

    def handle_client_hello(self):


    def run_server(self):
        """Runs the ProtoChat server, accepting and handling clients."""
        while True:
            conn, cliaddr = self.servsock.accept()
            print(f"Client connected from {cliaddr[0]}:{cliaddr[1]}")
            conn.close()

    def close(self):
        """Closes the server's resources."""
        for client in self.clients.values():
            client.close()
        self.servsock.close()


def main(args: argparse.Namespace):
    server_obj = ProtoServer(args.address, args.port)
    server_obj.run_server()


if __name__ == "__main__":
    args = parse_proto_args()
    main(args)
