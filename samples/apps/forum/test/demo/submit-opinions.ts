// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import * as fs from 'fs'
import * as path from 'path'
import glob from 'glob'
import bent from 'bent'
import csvparse from 'csv-parse/lib/sync'
import { NODE_ADDR } from '../util'
import { SubmitOpinionsRequest } from '../../src/controllers/poll'

const ENDPOINT_URL = `${NODE_ADDR}/app/polls`

function getFakeAuth(userId: string) {
    // See src/util.ts.
    return {
      'authorization': `Bearer user=${userId}'`
    }
}

interface CSVRow {
    Topic: string
    Opinion: string
}

async function main() {
    const args = process.argv.slice(2)
    if (args.length !== 1) {
        console.error('Usage: npm run submit-opinions folder')
        process.exit(1)
    }
    const folder = args[0]
    const csvPaths = glob.sync(folder + '/*_opinions.csv')
    for (const csvPath of csvPaths) {
        const user = path.basename(csvPath).replace('_opinions.csv', '')
        const csv = fs.readFileSync(csvPath)
        const rows: CSVRow[] = csvparse(csv, {columns: true, skipEmptyLines: true})

        const req: SubmitOpinionsRequest = {}
        for (const row of rows) {
            req[row.Topic] = { opinion: isNumber(row.Opinion) ? parseFloat(row.Opinion) : row.Opinion }
        }
        console.log('Submitting opinions for user ' + user)
        try {
            await bent('PUT', 204)(`${ENDPOINT_URL}/all`, req, getFakeAuth(user))
        } catch (e) {
            console.error('Error: ' + await e.text())
            process.exit(1)
        }
    }
}

function isNumber(s: string) {
    return !Number.isNaN(Number(s))
}

main()
