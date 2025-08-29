# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from aiohttp import web
from datetime import datetime, UTC
import asyncio
import random


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

    for url, port in [
        ("::1", 0),
        ("127.0.0.1", 0),
        ("127.100.0.1", 0),
        ("127.100.0.52", 10001),
    ]:
        try:
            runner = web.AppRunner(app)
            await runner.setup()

            site = web.TCPSite(runner, url, port)
            await site.start()

            print(f"Listening on {url}:{port}")

            await runner.cleanup()

        except Exception as e:
            print(f"Failed to bind to {url}:{port}: {e}")
    exit(1)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
