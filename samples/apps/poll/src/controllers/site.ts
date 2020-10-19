
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

const POLLS_HTML = `
<!DOCTYPE html>
<html>
<body>

User: <span id="user"></span><br /><br />

Topic:
<input type="text" id="input-topic">
<br />

Type: 
<input type="radio" name="input-poll-type" value="number"> Numeric
<input type="radio" name="input-poll-type" value="string"> String
<br />
<button id="create-poll-btn">Create Poll</button>

<script>
const apiUrl = window.location.origin + '/app/polls'
const $ = document.querySelector.bind(document)

function getRandomInt(min, max) {
    min = Math.ceil(min)
    max = Math.floor(max)
    return Math.floor(Math.random() * (max - min + 1)) + min
}

let user = 'user' + getRandomInt(0, 1000).toString()

$('#user').innerHTML = user

$('#create-poll-btn').addEventListener('click', async () => {
    const typeEl = $('input[name=input-poll-type]:checked')
    if (!typeEl) {
        window.alert('Poll type must be selected')
        return
    }
    const type = typeEl.value
    const topic = $('#input-topic').value
    try {
        await createPoll(topic, user, type)
    } catch (e) {
        window.alert(e)
        return
    }
    window.alert('Successfully created poll for topic "' + topic + '".')
    window.location = window.location + topic
})

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

</script>
</body>
</html>
`

const POLL_HTML = `
<!DOCTYPE html>
<html>
<body>

User: <span id="user"></span><br /><br />

Topic: <span id="poll-topic"></span><br /><br />

Opinion: <input type="text" id="input-opinion" /><br />
<button id="submit-opinion-btn">Submit Opinion</button>
<br /><br />

<button id="get-aggregated-opinions-btn">Get aggregated opinions</button><br />
<pre id="stuff"></pre>

<script>
const apiUrl = window.location.origin + '/app/polls'
const urlParams = new URLSearchParams(window.location.search)
const topic = urlParams.get('topic')

const $ = document.querySelector.bind(document)

$('#poll-topic').innerHTML = topic

function getRandomInt(min, max) {
    min = Math.ceil(min)
    max = Math.floor(max)
    return Math.floor(Math.random() * (max - min + 1)) + min
}

let user = 'user' + getRandomInt(0, 1000).toString()

$('#user').innerHTML = user

$('#submit-opinion-btn').addEventListener('click', async () => {
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
    window.alert('Successfully submitted opinion.')
})

$('#get-aggregated-opinions-btn').addEventListener('click', async () => {
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

@Hidden()
@Route("site/polls")
export class PollsSiteController extends Controller {

    // TODO should be /polls and /polls/{topic}

    //@Get('{topic}')
    @Get()
    public get(
        //@Path() topic: string
        @Query() topic: string,
        //@Header() authorization: string,
    ): any {
        this.setHeader('content-type', 'text/html')
        if (topic) {
            return POLL_HTML
        } else {
            return POLLS_HTML
        }
    }
}