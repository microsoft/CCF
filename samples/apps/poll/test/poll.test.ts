import { assert } from 'chai'
import bent from 'bent'
import { NODE_ADDR, setupMochaCCFSandbox } from './util'
import {
  CreatePollRequest, SubmitOpinionRequest, 
  NumericPollResponse, StringPollResponse,
  MINIMUM_OPINION_THRESHOLD
} from '../src/controllers/poll'

const APP_BUNDLE_DIR = 'dist'
const ENDPOINT_URL = `${NODE_ADDR}/app/polls`

// Note: In order to use a single CCF instance (and hence keep tests fast),
// each test uses a different poll topic.

function getFakeAuth(userId: number) {
  // See src/util.ts.
  return {
    'authorization': `Bearer user=dummy-${userId}'`
  }
}

describe('/polls', function () {
  setupMochaCCFSandbox(APP_BUNDLE_DIR)

  describe('POST /{topic}', function () {
    it('creates numeric polls', async function () {
      const topic = 'post-a'
      const body: CreatePollRequest = {
        type: "number"
      }
      await bent('POST', 201)(`${ENDPOINT_URL}?topic=${topic}`, body, getFakeAuth(1))
    })
    it('creates string polls', async function () {
      const topic = 'post-b'
      const body: CreatePollRequest = {
        type: "string"
      }
      await bent('POST', 201)(`${ENDPOINT_URL}?topic=${topic}`, body, getFakeAuth(1))
    })
    it('rejects creating polls with an existing topic', async function () {
      const topic = 'post-c'
      const body: CreatePollRequest = {
        type: "string"
      }
      await bent('POST', 201)(`${ENDPOINT_URL}?topic=${topic}`, body, getFakeAuth(1))
      await bent('POST', 403)(`${ENDPOINT_URL}?topic=${topic}`, body, getFakeAuth(1))
    })
    it('rejects creating polls without authorization', async function () {
      const topic = 'post-d'
      const body: CreatePollRequest = {
        type: "string"
      }
      // 422 = validation error, because the header is missing, should be 401
      await bent('POST', 422)(`${ENDPOINT_URL}?topic=${topic}`, body)
    })
  })
  describe('PUT /{topic}', function () {
    it('stores opinions to a topic', async function () {
      const topic = 'put-a'
      const pollBody: CreatePollRequest = {
        type: "number"
      }
      await bent('POST', 201)(`${ENDPOINT_URL}?topic=${topic}`, pollBody, getFakeAuth(1))

      const opinionBody: SubmitOpinionRequest = {
        opinion: 1.2
      }
      await bent('PUT', 204)(`${ENDPOINT_URL}?topic=${topic}`, opinionBody, getFakeAuth(1))
    })
    it('rejects opinions with mismatching data type', async function () {
      const topic = 'put-b'
      const pollBody: CreatePollRequest = {
        type: "number"
      }
      await bent('POST', 201)(`${ENDPOINT_URL}?topic=${topic}`, pollBody, getFakeAuth(1))

      const opinionBody: SubmitOpinionRequest = {
        opinion: "foo"
      }
      await bent('PUT', 400)(`${ENDPOINT_URL}?topic=${topic}`, opinionBody, getFakeAuth(1))
    })
    it('rejects opinions for unknown topics', async function () {
      const body: SubmitOpinionRequest = {
        opinion: 1.2
      }
      await bent('PUT', 404)(`${ENDPOINT_URL}?topic=non-existing`, body, getFakeAuth(1))
    })
    it('rejects opinions without authorization', async function () {
      const topic = 'put-c'
      const pollBody: CreatePollRequest = {
        type: "number"
      }
      await bent('POST', 201)(`${ENDPOINT_URL}?topic=${topic}`, pollBody, getFakeAuth(1))

      const opinionBody: SubmitOpinionRequest = {
        opinion: 1.2
      }
      // 422 = validation error, because the header is missing, should be 401
      await bent('PUT', 422)(`${ENDPOINT_URL}?topic=${topic}`, opinionBody)
    })
  })
  describe('GET /{topic}', function () {
    it('returns aggregated numeric poll opinions', async function () {
      const topic = 'get-a'
      const pollBody: CreatePollRequest = {
        type: "number"
      }
      await bent('POST', 201)(`${ENDPOINT_URL}?topic=${topic}`, pollBody, getFakeAuth(1))

      let opinions = [1.5, 0.9, 1.2]
      for (let i = 0; i < opinions.length; i++) {
        const opinionBody: SubmitOpinionRequest = {
          opinion: opinions[i]
        }
        await bent('PUT', 204)(`${ENDPOINT_URL}?topic=${topic}`, opinionBody, getFakeAuth(i))
      }

      let aggregated: NumericPollResponse =
        await bent('GET', 'json', 200)(`${ENDPOINT_URL}?topic=${topic}`, null, getFakeAuth(1))
      assert.equal(aggregated.statistics.median, opinions[2])
    })
    it('returns aggregated string poll opinions', async function () {
      const topic = 'get-b'
      const pollBody: CreatePollRequest = {
        type: "string"
      }
      await bent('POST', 201)(`${ENDPOINT_URL}?topic=${topic}`, pollBody, getFakeAuth(1))

      let opinions = ["foo", "foo", "bar"]
      for (let i = 0; i < opinions.length; i++) {
        const opinionBody: SubmitOpinionRequest = {
          opinion: opinions[i]
        }
        await bent('PUT', 204)(`${ENDPOINT_URL}?topic=${topic}`, opinionBody, getFakeAuth(i))
      }

      let aggregated: StringPollResponse = 
        await bent('GET', 'json', 200)(`${ENDPOINT_URL}?topic=${topic}`, null, getFakeAuth(1))
      assert.equal(aggregated.statistics.counts["foo"], 2)
      assert.equal(aggregated.statistics.counts["bar"], 1)
    })
    it('rejects returning aggregated opinions below the required opinion count threshold', async function () {
      const topic = 'get-c'
      const pollBody: CreatePollRequest = {
        type: "number"
      }
      await bent('POST', 201)(`${ENDPOINT_URL}?topic=${topic}`, pollBody, getFakeAuth(1))

      for (let i = 0; i < MINIMUM_OPINION_THRESHOLD - 1; i++) {
        const opinionBody: SubmitOpinionRequest = {
          opinion: 1.0
        }
        await bent('PUT', 204)(`${ENDPOINT_URL}?topic=${topic}`, opinionBody, getFakeAuth(i))
      }

      await bent('GET', 403)(`${ENDPOINT_URL}?topic=${topic}`, null, getFakeAuth(1))
    })
    it('rejects returning aggregated opinions for unknown topics', async function () {
      await bent('GET', 404)(`${ENDPOINT_URL}?topic=non-existing`, null, getFakeAuth(1))
    })
  })
})
