"""Check a real Streamlit session on the caller's own synthetic demo."""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from urllib.parse import urlsplit

import websockets
from streamlit.proto.BackMsg_pb2 import BackMsg
from streamlit.proto.ForwardMsg_pb2 import ForwardMsg


async def check_session(base_url: str) -> None:
    origin = urlsplit(base_url)
    if (
        origin.scheme not in {"http", "https"}
        or not origin.hostname
        or origin.username is not None
        or origin.password is not None
        or origin.path not in {"", "/"}
        or origin.query
        or origin.fragment
    ):
        raise ValueError("base URL must be the origin of your own demo service")
    scheme = "wss" if origin.scheme == "https" else "ws"
    messages: Counter[str] = Counter()
    async with websockets.connect(
        f"{scheme}://{origin.netloc}/_stcore/stream",
        origin=f"{origin.scheme}://{origin.netloc}",
        subprotocols=["streamlit"],
        open_timeout=15,
        max_size=25 * 1024 * 1024,
    ) as connection:
        request = BackMsg()
        request.rerun_script.SetInParent()
        await connection.send(request.SerializeToString())
        for _ in range(500):
            reply = ForwardMsg()
            reply.ParseFromString(await asyncio.wait_for(connection.recv(), timeout=30))
            kind = reply.WhichOneof("type")
            if kind is not None:
                messages[kind] += 1
            if (
                kind == "delta"
                and reply.delta.HasField("new_element")
                and reply.delta.new_element.HasField("exception")
            ):
                raise RuntimeError("Streamlit rendered an application exception")
            if kind == "script_finished":
                if not messages["new_session"] or not messages["delta"]:
                    raise RuntimeError("Streamlit did not render its initial UI")
                print("Streamlit WebSocket session passed; UI rendered without errors")
                return
        raise RuntimeError("Streamlit session did not finish within the message bound")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:10000")
    args = parser.parse_args()
    asyncio.run(check_session(args.base_url))


if __name__ == "__main__":
    main()
