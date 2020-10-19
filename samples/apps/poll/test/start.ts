import { spawnSync } from 'child_process'
import * as util from './util'

const app_bundle_dir = 'dist'

function main() {
    const {command, args} = util.getCCFSandboxCmdAndArgs(app_bundle_dir)
    spawnSync(command, args, { stdio: 'inherit' })
}

main()
