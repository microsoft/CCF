import { ChildProcess, spawn } from 'child_process'
import * as path from 'path'

// accept self-signed certs
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

const NODE_HOST = '127.0.0.1:8000'
export const NODE_ADDR = 'https://' + NODE_HOST

export function setupMochaCCFSandbox(app_bundle_dir: string) {
    const CCF_SANDBOX_ARGS = [
        '--node', NODE_HOST,
        '--js-app-bundle', app_bundle_dir,
        '--workspace', '.workspace_ccf'
    ]
    if (process.env.VERBOSE == '1') {
        CCF_SANDBOX_ARGS.push('--verbose')
    }

    // This logic allows to run tests easily from a CCF install or the CCF repository.
    // Most of this will disappear once CCF's build folder uses the same layout as an install.
    let CCF_SANDBOX_SCRIPT: string
    const CCF_REPO_ROOT = path.join('..', '..', '..')
    const CCF_BINARY_DIR = process.env.CCF_BINARY_DIR || path.join(CCF_REPO_ROOT, 'build')
    if (path.basename(CCF_BINARY_DIR) === 'bin') {
        // ccf install tree
        CCF_SANDBOX_SCRIPT = path.join(CCF_BINARY_DIR, 'sandbox.sh')
    } else {
        // ccf repo tree
        CCF_SANDBOX_SCRIPT = path.join(CCF_REPO_ROOT, 'tests', 'sandbox', 'sandbox.sh')
        CCF_SANDBOX_ARGS.push('--binary-dir', CCF_BINARY_DIR)
    }

    let sandboxProcess: ChildProcess
    before(function () {
        this.timeout(20000) // first time takes longer due to venv install
        return new Promise((resolve, reject) => {
            sandboxProcess = spawn(CCF_SANDBOX_SCRIPT, CCF_SANDBOX_ARGS, {
                stdio: ['pipe', 'pipe', 'inherit'],
                timeout: 30000 // sandbox startup + max test duration
            })
            sandboxProcess.on('exit', reject)
            sandboxProcess.stdout.on('data', data => {
                const msg = data.toString()
                console.log(msg)
                if (msg.includes('Started CCF network')) {
                    setTimeout(() => {
                        sandboxProcess.off('exit', reject)
                        resolve()
                    }, 500) // bug in CCF not being ready just yet
                }
            })
        })
    })

    after(function () {
        this.timeout(5000)
        return new Promise((resolve, reject) => {
            sandboxProcess.on('exit', () => {
                resolve()
            })
            sandboxProcess.kill("SIGINT")
        })
    })
}