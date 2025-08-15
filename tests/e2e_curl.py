# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from aiohttp import web
import json
from datetime import datetime, UTC
import asyncio
import random

async def echo_handler(request):
    # Extract headers as list of [name, value] pairs
    headers = [[name, value] for name, value in request.headers.items()]
    
    # Read body
    body = await request.text()

    time_received = datetime.now(UTC)
    
    # Add random delay between 0 and 1 second
    delay = random.random() / 100  # Returns float between 0.0 and 1.0
    await asyncio.sleep(delay)
    
    # Build response data
    response_data = {
        "headers": headers,
        "body": body,
        "metadata": {
            "method": request.method,
            "path": request.path_qs,
            "timestamp": time_received.isoformat(),
            "delay_seconds": delay
        }
    }
    
    return web.json_response(response_data)

async def main():
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', echo_handler)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 8080)
    await site.start()
    
    print('Echo server running on http://127.0.0.1:8080')

    # call ./curl_test to run the load generator
    cmd = "./curl_test"
    process = await asyncio.create_subprocess_shell(cmd)
    await process.wait()

    exit(process.returncode)

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())