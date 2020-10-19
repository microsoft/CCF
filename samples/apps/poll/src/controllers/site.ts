
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

const COMMON_HTML = `
<script src="//cdn.jsdelivr.net/npm/jstat@1.9.4/dist/jstat.min.js"></script>
<script src="//cdn.plot.ly/plotly-1.57.0.min.js"></script>
<script>
const apiUrl = window.location.origin + '/app/polls'

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

async function getPoll(topic, user) {
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
        throw new Error('Could not retrieve poll: ' + error.message)
    }
    const opinions = await response.json()
    return opinions
}

function plotPoll(element, topic, data) {
    if (data.type == 'string') {
        plotStringPoll(element, topic, data)
    } else {
        plotNumberPoll(element, topic, data)
    }
}

const margin = {l: 30, r: 30, t: 30, b: 30}

function plotNumberPoll(element, topic, data) {
    const mean = data.statistics.mean
    const std = data.statistics.std
    const normal = jStat.normal(mean, std)
    const xs = []
    const ys = []
    for (let i = mean - std*2; i < mean + std*2; i += 0.01) {
        xs.push(i)
        ys.push(normal.pdf(i))
    }
    
    const trace = {
        x: xs,
        y: ys,
        opacity: 0.5,
        line: {
            color: 'rgba(255, 0, 0)',
            width: 4
        },
        type: 'scatter'
    }

    const shapes = [{
        type: 'line',
        yref: 'paper',
        x0: mean,
        y0: 0,
        x1: mean,
        y1: 1,
        line:{
            color: 'black',
            width: 3,
        }
    }, {
        type: 'line',
        yref: 'paper',
        x0: mean - std,
        y0: 0,
        x1: mean - std,
        y1: 1,
        line:{
            color: 'black',
            width: 2,
        }
    }, {
        type: 'line',
        yref: 'paper',
        x0: mean + std,
        y0: 0,
        x1: mean + std,
        y1: 1,
        line:{
            color: 'black',
            width: 2,
        }
    }]
    if (data.opinion) {
        shapes.push({
            type: 'line',
            yref: 'paper',
            x0: data.opinion,
            y0: 0,
            x1: data.opinion,
            y1: 1,
            line:{
                color: 'red',
                width: 2,
            }
        })
    }

    Plotly.newPlot(element, [trace], {
        title: topic,
        shapes: shapes,
        xaxis: {
            zeroline: false
        },
        yaxis: {
            zeroline: false
        },
        margin: margin
      }, {displayModeBar: false})
}

function plotStringPoll(element, topic, data) {
    const strings = Object.keys(data.statistics.counts)
    const counts = Object.values(data.statistics.counts)
    const colors = strings.map(s => s == data.opinion ? 'rgba(222,45,38,0.8)' : 'rgba(204,204,204,1)')
    const trace = {
        x: strings,
        y: counts,
        marker:{
            color: colors
        },
        type: 'bar'
    }
    Plotly.newPlot(element, [trace], {
        title: topic,
        margin: margin
    }, {displayModeBar: false})
}
</script>
`

const POLLS_HTML = `
<!DOCTYPE html>
<html>
<style>
.plot {
    width: 300px;
    height: 150px;
    float: left;
}
</style>
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
<br />
<br />
Topics (comma-separated): <input type="text" id="input-topics" /><br />
<button id="plot-polls-btn">Plot</button>

<div id="plots"></div>

${COMMON_HTML}

<script>
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

$('#plot-polls-btn').addEventListener('click', async () => {
    const topics = $('#input-topics').value.split(',')
    const plotsEl = $('#plots')
    plotsEl.innerHTML = topics.map((topic,i) => '<div class="plot" id="plot_' + i + '"></div>').join('')
    for (let [i, topic] of topics.entries()) {
        const plotEl = $('#plot_' + i)
        const poll = await getPoll(topic, user)
        plotPoll('plot_' + i, topic, poll)
    }
})

// test data
async function createTestData() {
    let topics = []
    for (let i=0; i < 12; i++) {
        let topic = 'topic ' + i
        topics.push(topic)
        const type = Math.random() > 0.5 ? 'string' : 'number'
        await createPoll(topic, 'user0', type)
        for (let j=0; j < 5; j++) {
            let opinion = type == 'string' ? 'foo' + (j % 3) : Math.random() * i
            await submitOpinion(topic, j == 0 ? user : 'user' + j, opinion)
        }
    }
    $('#input-topics').value = topics.join(',')
}
createTestData()

</script>
</body>
</html>
`

const POLL_HTML = `
<!DOCTYPE html>
<html>
<body>

User: <span id="user"></span><br /><br />

Topic: <span id="poll-topic"></span><br />
Type: <span id="poll-type"></span>
<br /><br />

Opinion: <input type="text" id="input-opinion" /><br />
<button id="submit-opinion-btn">Submit Opinion</button>
<br /><br />

<div id="plot" style="width: 500px; height: 300px"></div>

${COMMON_HTML}

<script>
const urlParams = new URLSearchParams(window.location.search)
const topic = urlParams.get('topic')
let type = null

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
    if (type === 'number') {
        opinion = parseFloat(opinion)
    }
    try {
        await submitOpinion(topic, user, opinion)
    } catch (e) {
        window.alert(e)
        return
    }
    await updatePoll()
    window.alert('Successfully submitted opinion.')
})

async function updatePoll() {
    try {
        var poll = await getPoll(topic, user)
    } catch (e) {
        window.alert(e)
        return
    }
    console.log(poll)
    type = poll.type
    $('#poll-type').innerHTML = poll.type
    if (poll.statistics) {
        plotPoll('plot', topic, poll)
    }
}

updatePoll()

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