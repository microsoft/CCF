import * as fs from 'fs'
import bent from 'bent'
import csvparse from 'csv-parse/lib/sync'
import { NODE_ADDR } from './util'
import { SubmitOpinionsRequest } from '../src/controllers/poll'

const ENDPOINT_URL = `${NODE_ADDR}/app/polls`

function getFakeAuth(userId: string) {
    // See src/util.ts.
    return {
      'authorization': `Bearer user=${userId}'`
    }
}

interface CSVRow {
    topic: string
    opinion: string
}

async function main() {
    const args = process.argv.slice(2)
    if (args.length !== 2) {
        console.error('Usage: npm run submit-opinions user123 opinions.csv')
        process.exit(1)
    }
    const user = args[0]
    const csv = fs.readFileSync(args[1])
    const rows: CSVRow[] = csvparse(csv, {columns: ['topic', 'opinion'], skipEmptyLines: true})

    const req: SubmitOpinionsRequest = {}
    for (const row of rows) {
        req[row.topic] = { opinion: isNumber(row.opinion) ? parseFloat(row.opinion) : row.opinion }
    }
    console.log('Submitting opinions for user ' + user)
    try {
        await bent('PUT', 204)(`${ENDPOINT_URL}/all`, req, getFakeAuth(user))
    } catch (e) {
        console.error('Error: ' + await e.text())
        process.exit(1)
    }
}

function isNumber(s: string) {
    return !Number.isNaN(Number(s))
}

main()
