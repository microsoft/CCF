import * as path from 'path'
import { ChildProcess, spawn } from 'child_process'
import { assert } from 'chai'
import fetch from 'node-fetch'
import { CreatePollRequest } from '../src/controllers/poll'

// accept self-signed certs
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

let CCF_SANDBOX_SCRIPT: string
if (process.env.CCF_DIR) {
  // ccf install tree
  CCF_SANDBOX_SCRIPT = path.join(process.env.CCF_DIR, 'bin', 'sandbox.sh')
} else {
  // ccf repo tree
  CCF_SANDBOX_SCRIPT = path.join('..', '..', '..', 'tests', 'sandbox', 'sandbox.sh')
}

const APP_BUNDLE_DIR = 'dist'

const CCF_SANDBOX_ARGS = ['--js-app-bundle', APP_BUNDLE_DIR]

const NODE_ADDR = 'https://127.0.0.1:8000'

let sandboxProcess: ChildProcess
beforeEach(function() {
  this.timeout(10000)
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
        sandboxProcess.off('exit', reject)
        resolve()
      }
    })    
  })
})

afterEach(function() {
  this.timeout(5000)
  return new Promise((resolve, reject) => {
    sandboxProcess.on('exit', () => {
      resolve()
    })
    sandboxProcess.kill("SIGINT")
  })
})

describe('/polls', function () {
  describe('POST /{topic}', function () {
    it('creates a new poll', async function () {
      const topic = 'foo'
      const response = await fetch(`${NODE_ADDR}/app/polls/${topic}`)
      const text = await response.text()
      assert.equal(response.status, 201, text)
    })
  })
})
