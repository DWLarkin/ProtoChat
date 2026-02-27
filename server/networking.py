"""Defines codes and helper functions related to networking."""

import logging
import socket

from enum import IntEnum, auto


class NetworkConstants(IntEnum):
    MAX_LEN = 4096
    MAX_NAME = 255  # Including \0, when it comes to outbound
    HELLO_HDR_LEN = 2
    MAX_HELLO = MAX_NAME + HELLO_HDR_LEN
    BASE_HDR_LEN = 3
    CHAT_HDR_LEN = BASE_HDR_LEN + 1


class ProtocolCodes(IntEnum):
    INVALID_CODE = 0
    CLIENT_HELLO = auto()
    SERVER_ACK = auto()
    CHAT_MESSAGE = auto()
    CLIENT_DISCONNECT = auto()
    CLIENT_LOST = auto()
    FILE_UPLOAD = auto()
    FILE_DOWNLOAD = auto()
    OUT_OF_BOUNDS = auto()


def send_all(conn: socket.socket, data: bytes, logger: logging.Logger) -> int:
    """Attempts to send all provided data.

    Args:
        conn (socket.socket): The socket to send on.
        data (bytes): The data to send.
        logger (logging.Logger): The logger to output to.

    Returns:
        The number of bytes sent, or -1 on disconnection or send error.

    """
    total_sent = 0

    try:
        while data:
            to_send = data[: NetworkConstants.MAX_LEN]

            bytes_sent = conn.send(to_send, 0)
            if bytes_sent == 0:
                raise ConnectionResetError("Client disconnected on send") from err

            data = data[bytes_sent:]
            total_sent += bytes_sent

        return total_sent
    except BlockingIOError:
        return total_sent
    except OSError as err:
        raise ConnectionAbortedError("Send failure") from err


def recv_all(conn: socket.socket, length: int, logger: logging.Logger) -> bytes:
    """Attempts to recv all requested bytes.

    Args:
        conn (socket.socket): The socket to recv on.
        length (int): The number of bytes to recv.
        logger (logging.Logger): The logger to output to.

    Returns:
        Whatever bytes are received, or no bytes on socket disconnect/error.

    """
    all_received = bytearray()
    amt_remaining = length

    while amt_remaining > 0:
        recv_amt = (
            NetworkConstants.MAX_LEN
            if amt_remaining > NetworkConstants.MAX_LEN
            else amt_remaining
        )

        try:
            recv_ret = conn.recv(recv_amt, 0)
        except BlockingIOError:
            return all_received
        except OSError as err:
            raise ConnectionAbortedError("Recv failure") from err
        if not recv_ret:
            raise ConnectionResetError("Client disconnected on recv")

        all_received += recv_ret
        amt_remaining -= len(recv_ret)

    return all_received
