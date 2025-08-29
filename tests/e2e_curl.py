# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from aiohttp import web
from datetime import datetime, UTC
import asyncio
import random
import os


async def echo_handler(request):
    # Extract headers as list of [name, value] pairs
    headers = [[name, value] for name, value in request.headers.items()]

    # Read body
    body = await request.text()

    time_received = datetime.now(UTC)

    # Add random delay between 0 and 10 millisecond
    delay = random.random() / 100
    await asyncio.sleep(delay)

    # Build response data
    response_data = {
        "headers": headers,
        "body": body,
        "metadata": {
            "method": request.method,
            "path": request.path_qs,
            "timestamp": time_received.isoformat(),
            "delay_seconds": delay,
        },
    }

    return web.json_response(response_data)


async def main():
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", echo_handler)

    runner = web.AppRunner(app)
    await runner.setup()

    base_addr = "127.0.0.1"
    site = web.TCPSite(runner, base_addr, 0)
    await site.start()

    sockets = site._server.sockets
    if not sockets:
        raise RuntimeError("Failed to start server")
    port = sockets[0].getsockname()[1]
    addr = f"{base_addr}:{port}"

    print(f"Echo server running on http://{addr}")

    env = os.environ.copy()
    env["ECHO_SERVER_ADDR"] = str(addr)

    cmd = "./curl_test"
    process = await asyncio.create_subprocess_shell(cmd, env=env)
    await process.wait()
    exit(process.returncode)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
