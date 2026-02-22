#!/usr/bin/env python3
"""Defines and potentially runs a ProtoChat server."""
import argparse
import socket
import struct

from dataclasses import field
from enum import IntEnum, auto


class NetworkConstants(IntEnum):
    MAX_RECV = 4096


class ProtocolCodes(IntEnum):
    INVALID_CODE = 0
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


def recv_all(conn: socket.socket, length: int) -> bytes:
    """Attempts to recv all requested bytes.

    Args:
        conn (socket.socket): The socket to recv on.
        length (int): The number of bytes to recv.

    Returns:
        Whatever bytes are received, or no bytes on socket disconnect/error.

    """
    all_received = bytearray()
    amt_remaining = length

    while amt_remaining > 0:
        recv_amt = NetworkConstants.MAX_RECV if amt_remaining > NetworkConstants.MAX_RECV else amt_remaining

        try:
            recv_ret = conn.recv(recv_amt, 0)
        except OSError:
            print("Recv failure")
            return bytes()

        if not recv_ret:
            print("Peer disconnected")
            return bytes()

        all_received += recv_ret
        amt_remaining -= len(recv_ret)

    return all_received


class ProtoClient:
    """Class-based handler for ProtoChat clients."""

    def __init__(self, name: str, conn: socket.socket):
        self.name = name
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
        self.clients: list[ProtoClient] = field(default_factory=list())

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

    def handle_client_hello(self, conn: socket.socket):
        recv_bytes = recv_all(conn, 2)  # task code + name length
        if not recv_bytes or recv_bytes[0] != ProtocolCodes.CLIENT_HELLO:
            conn.close()
            return

        encoded_name = recv_all(conn, recv_bytes[1])
        if not encoded_name:
            conn.close()
            return

        try:
            client_name = encoded_name.decode("utf-8")
        except UnicodeDecodeError:
            conn.close()
            return

        server_ack = struct.pack(
            f"!BB{len(encoded_name)}s",
            ProtocolCodes.SERVER_ACK,
            len(encoded_name),
            encoded_name,
        )

        try:
            conn.sendall(server_ack, 0)
        except OSError:
            conn.close()
            return

        print(f"New client name is {client_name}")

    def run_server(self):
        """Runs the ProtoChat server, accepting and handling clients."""
        while True:
            conn, cliaddr = self.servsock.accept()
            print(f"Client connected from {cliaddr[0]}:{cliaddr[1]}")

            self.handle_client_hello(conn)

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
