
import {
    Header,
    Query,
    SuccessResponse,
    Response,
    Hidden,
    Controller,
    Get,
    Route,
} from "@tsoa/runtime";

import { ValidateErrorResponse, ValidateErrorStatus } from "../error_handler"
import { parseAuthToken } from "../util"


@Hidden()
@Route("site")
export class SiteController extends Controller {

    //@Get('{topic}')
    @Get()
    public getPoll(
        //@Path() topic: string
        @Query() topic: string,
        //@Header() authorization: string,
    ): any {
        this.setHeader('content-type', 'text/html')
        return `
<!DOCTYPE html>
<html>
<body>

User: <input type="text" id="input-user" /><br /><br />

<input type="radio" name="input-poll-type" value="number"> Numeric
<input type="radio" name="input-poll-type" value="string"> String
<button id="create-poll-btn">Create Poll</button><br /><br />

Opinion: <input type="text" id="input-opinion" />
<button id="submit-opinion-btn">Submit Opinion</button><br /><br />

<button id="get-aggregated-opinions-btn">Get aggregated opinions</button>
<pre id="stuff"></pre>

<script>
const apiUrl = window.location.origin + '/app/polls'
const urlParams = new URLSearchParams(window.location.search)
const topic = urlParams.get('topic')

const $ = document.querySelector.bind(document)

function getRandomInt(min, max) {
    min = Math.ceil(min)
    max = Math.floor(max)
    return Math.floor(Math.random() * (max - min + 1)) + min
}

$('#input-user').value = 'user' + getRandomInt(0, 1000).toString()

$('#create-poll-btn').addEventListener('click', async () => {
    const typeEl = $('input[name=input-poll-type]:checked')
    if (!typeEl) {
        window.alert('Poll type must be selected')
        return
    }
    const type = typeEl.value
    const user = $('#input-user').value
    try {
        await createPoll(topic, user, type)
    } catch (e) {
        window.alert(e)
        return
    }
    window.alert('success')
})

$('#submit-opinion-btn').addEventListener('click', async () => {
    const user = $('#input-user').value
    let opinion = $('#input-opinion').value
    if (!Number.isNaN(Number(opinion))) {
        opinion = parseFloat(opinion)
    }
    try {
        await submitOpinion(topic, user, opinion)
    } catch (e) {
        window.alert(e)
        return
    }
    window.alert('success')
})

$('#get-aggregated-opinions-btn').addEventListener('click', async () => {
    const user = $('#input-user').value
    try {
        var opinions = await getAggregatedOpinions(topic, user)
    } catch (e) {
        window.alert(e)
        return
    }
    console.log(opinions)
    $('#stuff').innerHTML = JSON.stringify(opinions)
})

async function getAggregatedOpinions(topic, user) {
    const response = await fetch(apiUrl + '?topic=' + topic, {
        method: 'GET',
        headers: {
            'content-type': 'application/json',
            'authorization': 'Bearer user=' + user,
        }
    })
    if (!response.ok) {
        const error = await response.json()
        console.error(error)
        throw new Error('Could not retrieve aggregated opinions: ' + error.message)
    }
    const opinions = await response.json()
    return opinions
}

async function createPoll(topic, user, type) {
    const response = await fetch(apiUrl + '?topic=' + topic, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            'authorization': 'Bearer user=' + user,
        },
        body: JSON.stringify({
            type: type
        })
    })
    if (!response.ok) {
        const error = await response.json()
        console.error(error)
        throw new Error('Could not create poll: ' + error.message)
    }
}

async function submitOpinion(topic, user, opinion) {
    const response = await fetch(apiUrl + '?topic=' + topic, {
        method: 'PUT',
        headers: {
            'content-type': 'application/json',
            'authorization': 'Bearer user=' + user,
        },
        body: JSON.stringify({
            opinion: opinion
        })
    })
    if (!response.ok) {
        const error = await response.json()
        console.error(error)
        throw new Error('Could not submit opinion: ' + error.message)
    }
}

</script>
</body>
</html>
        `
    }
}