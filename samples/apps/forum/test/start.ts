// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { spawnSync } from 'child_process'
import * as util from './util'

const app_bundle_dir = 'dist'

function main() {
    const {command, args} = util.getCCFSandboxCmdAndArgs(app_bundle_dir)
    spawnSync(command, args, { stdio: 'inherit' })
}

main()
