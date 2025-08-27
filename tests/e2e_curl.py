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

    # print(f"{datetime.now(UTC)}: Replying to request to {request.path_qs} after {delay:.3f}s delay")

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


async def main(debug):
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", echo_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "::1", 8080)
    await site.start()

    print("Echo server running on http://::1:8080")

    cmd = "./curl_test"
    if debug:
        print(f"Run '{cmd}' to run the load generator")
        # wait forever
        await asyncio.Event().wait()
    process = await asyncio.create_subprocess_shell(cmd)
    await process.wait()

    exit(process.returncode)


if __name__ == "__main__":
    import asyncio
    import argparse

    parser = argparse.ArgumentParser(description="Run echo server")
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    asyncio.run(main(args.debug))
