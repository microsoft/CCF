// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { Hidden, Controller, Get, Route } from "@tsoa/runtime";

import { MS_APP_ID, MS_APP_ID_URI } from "../authentication";

const HEADER_HTML = `
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Forum</title>

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css" integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2" crossorigin="anonymous">

    <style>
      body {
        padding-top: 5rem;
      }
      @media (min-width: 1200px) {
        .container {
            max-width: 1250px;
        }
      }
      .start-info {
        padding: 3rem 1.5rem;
        text-align: center;
      }
      #login-btn {
          display: none;
          margin-left: 1rem;
      }
    </style>
  </head>
  <body>
  <script src="//code.jquery.com/jquery-3.5.1.slim.min.js" integrity="sha384-DfXdz2htPH0lsSSs5nCTpuj/zy4C+OGpamoFVy38MVBnE+IbbVYUew+OrCXaRkfj" crossorigin="anonymous"></script>
  <script src="//cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ho+j7jyWK8fNQe+A12Hb8AhRq26LrZ/JpcUGGOn+Y7RsweNrtN/tE3MoK7ZeZDyx" crossorigin="anonymous"></script>
  <script src="//cdn.jsdelivr.net/npm/js-cookie@3.0.0-rc.1/dist/js.cookie.min.js"></script>
  <script src="//cdn.jsdelivr.net/npm/jstat@1.9.4/dist/jstat.min.js"></script>
  <script src="//cdn.plot.ly/plotly-1.57.0.min.js"></script>
  <script src="//unpkg.com/papaparse@5.3.0/papaparse.min.js"></script>
  <script src="//alcdn.msauth.net/browser/2.4.1/js/msal-browser.min.js"></script>
  <script src="//cdn.jsdelivr.net/npm/jwt-decode@3.0.0/build/jwt-decode.js"></script>
  <script>
const apiUrl = window.location.origin + '/app/polls'
const siteUrl = window.location.origin + '/app/site'

// "CCF Demo App" app registration
const MS_APP_ID = "${MS_APP_ID}"
// Note: Even though a scope is not strictly required for this app,
// it is needed so that Microsoft produces standard-compliant JWTs.
// Creating and requesting a scope of our own app changes the token audience
// to our app instead of being Microsoft (which is the default).
// See also https://xsreality.medium.com/making-azure-ad-oidc-compliant-5734b70c43ff
// and https://docs.microsoft.com/en-us/azure/active-directory/develop/scenario-protected-web-api-overview.
const MS_LOGIN_SCOPES = ["${MS_APP_ID_URI}/Polls.Access"]

const msalInstance = new msal.PublicClientApplication({
    auth: {
        clientId: MS_APP_ID,
        // Only the start page is registered as redirect URI
        redirectUri: siteUrl
    }
})
async function handleRedirectLogin() {
    try {
        const tokenResponse = await msalInstance.handleRedirectPromise({})
        if (tokenResponse) {
            const jwt = tokenResponse.accessToken
            return jwt
        }
    } catch (err) {
        console.log(err)
    }
    return null
}

function login() {
    msalInstance.loginRedirect({
        scopes: MS_LOGIN_SCOPES
    })
}

async function initUser() {
    const jwtCookieName = 'jwt'
    const jwt = await handleRedirectLogin()
    if (jwt) {
        window.jwt = jwt
        Cookies.set(jwtCookieName, jwt)
    } else {
        window.jwt = Cookies.get(jwtCookieName)
    }
    console.log('JWT:', window.jwt)
}

function getUserName() {
    if (!window.jwt) {
        return 'not logged in'
    }
    const payload = jwt_decode(window.jwt)
    const user = payload.upn
    return user
}

function isLoggedIn() {
    return !!window.jwt
}
  </script>
  <script>
  window.$ = document.querySelector.bind(document)
  
  document.addEventListener("DOMContentLoaded", async () => {
    await initUser()
    $('#user').innerHTML = getUserName()
    $('#login-btn').style.display = isLoggedIn() ? 'none' : 'block'
    $('#login-btn').addEventListener('click', () => {
        login()
    })
  })
  
  function parseCSV(csv) {
      return Papa.parse(csv, {header: true, skipEmptyLines: true}).data
  }

  async function retrieve(url, method, body) {
    const response = await fetch(url, {
        method: method,
        headers: {
            'content-type': 'application/json',
            'authorization': 'Bearer ' + window.jwt,
        },
        body: body ? JSON.stringify(body) : undefined
    })
    if (!response.ok) {
        const error = await response.json()
        console.error(error)
        throw new Error(error.message)
    }
    return response
  }
  
  async function createPoll(topic, type) {
    const body = { type: type }
    await retrieve(apiUrl + '/' + topic, 'POST', body)
  }
  
  async function createPolls(polls) {
    const body = { polls: polls }
    await retrieve(apiUrl, 'POST', body)
  }
  
  async function submitOpinion(topic, opinion) {
    const body = { opinion: opinion }
    await retrieve(apiUrl + '/' + topic, 'PUT', body)
  }
  
  async function submitOpinions(opinions) {
    const body = { opinions: opinions }
    await retrieve(apiUrl, 'PUT', body)
  }
  
  async function getPoll(topic) {
      const response = await retrieve(apiUrl + '/' + topic, 'GET')
      const poll = await response.json()
      return poll
  }
  
  async function getPolls() {
    const response = await retrieve(apiUrl, 'GET')
    const polls = await response.json()
    return polls.polls
  }
  
  function plotPoll(element, topic, data) {
      if (!data.statistics) {
          plotEmptyPoll(element, topic)
      } else if (data.type == 'string') {
          plotStringPoll(element, topic, data)
      } else {
          plotNumberPoll(element, topic, data)
      }
  }
  
  const margin = {l: 30, r: 30, t: 50, b: 50}
  
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
      const xtickvals = [mean, mean - std, mean + std]

      if (data.opinion) {
          shapes.push({
              type: 'line',
              yref: 'paper',
              x0: data.opinion,
              y0: 0,
              x1: data.opinion,
              y1: 1,
              line:{
                  color: '#69c272',
                  width: 2,
              }
          })
          xtickvals.push(data.opinion)
      }
  
      Plotly.newPlot(element, [trace], {
          title: topic,
          shapes: shapes,
          xaxis: {
              zeroline: false,
              showgrid: false,
              tickvals: xtickvals,
              tickangle: 45,
              tickformat: ".1f",
          },
          yaxis: {
              visible: false,
              zeroline: false,
              showgrid: false,
          },
          margin: margin
        }, {displayModeBar: false})
  }
  
  function plotStringPoll(element, topic, data) {
      const strings = Object.keys(data.statistics.counts)
      const counts = Object.values(data.statistics.counts)
      const colors = strings.map(s => s == data.opinion ? '#69c272' : 'rgba(204,204,204,1)')
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
          margin: margin,
          yaxis: {
            visible: false,
            showgrid: false,
          },
      }, {displayModeBar: false})
  }
  
  function plotEmptyPoll(element, topic) {
      Plotly.newPlot(element, [], {
          title: topic,
          margin: margin,
          xaxis: {
            zeroline: false,
            showticklabels: false
          },
          yaxis: {
            zeroline: false,
            showticklabels: false
          },
          annotations: [{
            xref: 'paper',
            yref: 'paper',
            xanchor: 'center',
            yanchor: 'bottom',
            x: 0.5,
            y: 0.5,
            text: 'NOT ENOUGH DATA',
            showarrow: false
          }]
      }, {displayModeBar: false});
  }
  </script>

<nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
    <a class="navbar-brand" href="/app/site">Confidential Forum</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExampleDefault" aria-controls="navbarsExampleDefault" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarsExampleDefault">
        <ul class="navbar-nav mr-auto">
        <li class="nav-item">
            <a class="nav-link" href="/app/site/polls/create">Create Polls</a>
        </li>
        <li class="nav-item">
            <a class="nav-link" href="/app/site/opinions/submit">Submit Opinions</a>
        </li>
        <li class="nav-item">
            <a class="nav-link" href="/app/site/view">View Statistics</a>
        </li>
        </ul>
        <span class="navbar-text">
           User: <span id="user"></span>
        </span>
        <button id="login-btn" class="btn btn-outline-success">Login</button>
    </div>
</nav>
`;

const FOOTER_HTML = `
</body>
</html>
`;

const START_HTML = `
${HEADER_HTML}

<main role="main" class="container">

  <div class="start-info">
    <h1>Confidential Forum</h1>
    <p class="lead">
    This is a simple example application written in TypeScript for the <a href="http://github.com/microsoft/ccf">Confidential Consortium Framework</a>.
    </p>
  </div>
  <ol>
  <li>
    <a href="/app/site/polls/create">Create Polls</a> by providing a list of <i>Name</i>, <i>Type</i>, where <i>Type</i> is one of <b>number</b>, <b>string</b>.
  </li>
  <li>
    <a href="/app/site/opinions/submit">Submit Opinions</a> as a list of <i>Topic Name</i>, <i>Value</i>.
  </li>
  <li>
    Once enough users have posted opinions about a topic, compare <a href="/app/site/view">your opinion to the consensus</a>.
  </li>
  </ol>

</main>

${FOOTER_HTML}
`;

const SAMPLE_POLLS = `\`"Topic","Opinion Type"

"Contoso, Ltd - Country of Risk",string
"Woodgrove Bank - Country of Risk",string
"Proseware - Country of Risk",string
"Fabrikam - Country of Risk",string

"Contoso, Ltd - 1Y CDS Spread",number
"Woodgrove Bank - 1Y CDS Spread",number
"Proseware - 1Y CDS Spread",number
"Fabrikam - 1Y CDS Spread",number

"Contoso, Ltd - 3Y CDS Spread",number
"Woodgrove Bank - 3Y CDS Spread",number
"Proseware - 3Y CDS Spread",number
"Fabrikam - 3Y CDS Spread",number
\``;

const CREATE_POLLS_HTML = `
${HEADER_HTML}

<main role="main" class="container">

<div class="alert alert-success alert-dismissible fade">
    Polls created successfully.
    <button type="button" class="close" data-dismiss="alert">&times;</button>
</div>

    <textarea id="input-polls" rows="10" cols="70"
    class="text-monospace"
    placeholder="Topic, Opinion Type
Foo  , string
Bar  , number"
    ></textarea>
    <br />
    <button id="create-polls-btn" class="btn btn-primary">Create Polls</button>
    <button id="sample-polls-btn" class="btn btn-info">Load Sample Polls</button>

</main>

<script>
$('#create-polls-btn').addEventListener('click', async () => {
    const rows = parseCSV($('#input-polls').value)
    const polls = {}
    for (const row of rows) {
        polls[row['Topic']] = { type: row['Opinion Type'] }
    }
    try {
        await createPolls(polls)
    } catch (e) {
        window.alert(e)
        return
    }
    $('.alert').classList.add("show");
    $('#input-polls').value = ''
})

$('#sample-polls-btn').addEventListener('click', async () => {
    $('#input-polls').value = ${SAMPLE_POLLS}
})
</script>

${FOOTER_HTML}
`;

const SAMPLE_OPINIONS = `\`"Topic","Opinion"

"Contoso, Ltd - Country of Risk",Freedonia
"Woodgrove Bank - Country of Risk",Freedonia
"Proseware - Country of Risk",Freedonia
"Fabrikam - Country of Risk",Snowdonia
"Contoso, Ltd - 1Y CDS Spread",145
Woodgrove Bank - 1Y CDS Spread,148
Proseware - 1Y CDS Spread,144
Fabrikam - 1Y CDS Spread,270
"Contoso, Ltd - 3Y CDS Spread",153
Woodgrove Bank - 3Y CDS Spread,159
Proseware - 3Y CDS Spread,156
Fabrikam - 3Y CDS Spread,380
\``;

const SUBMIT_OPINIONS_HTML = `
${HEADER_HTML}

<main role="main" class="container">

<div class="alert alert-success alert-dismissible fade">
    Opinions submitted successfully.
    <button type="button" class="close" data-dismiss="alert">&times;</button>
</div>

    <textarea id="input-opinions" rows="10" cols="70"
    class="text-monospace"
    placeholder="Topic, Opinion
Foo  , abc
Bar  , 1.5"
    ></textarea>
    <br />
    <button id="submit-opinions-btn" class="btn btn-primary">Submit Opinions</button>
    <button id="sample-opinions-btn" class="btn btn-info">Load Sample Opinions</button>

</main>

<script>
$('#submit-opinions-btn').addEventListener('click', async () => {
    const rows = parseCSV($('#input-opinions').value)
    const opinions = {}
    for (let row of rows) {
        let opinion = row['Opinion']
        if (!Number.isNaN(Number(opinion))) {
            opinion = parseFloat(opinion)
        }
        opinions[row['Topic']] = { opinion: opinion }
    }
    try {
        await submitOpinions(opinions)
    } catch (e) {
        window.alert(e)
        return
    }
    $('.alert').classList.add("show");
    $('#input-opinions').value = ''
})

$('#sample-opinions-btn').addEventListener('click', async () => {
    $('#input-opinions').value = ${SAMPLE_OPINIONS}
})

</script>
${FOOTER_HTML}
`;

const VIEW_HTML = `
${HEADER_HTML}
<style>
.plot {
    width: 300px;
    height: 250px;
    float: left;
}
</style>

<main role="main" class="container">
    <div id="plots"></div>
</main>

<script>
async function main() {
    await initUser()
    const polls = await getPolls()
    const topics = Object.keys(polls)

    const plotsEl = $('#plots')
    plotsEl.innerHTML = topics.map((topic,i) => '<div class="plot" id="plot_' + i + '"></div>').join('')
    for (let [i, topic] of topics.entries()) {
        plotPoll('plot_' + i, topic, polls[topic])
    }
}
main()

</script>
${FOOTER_HTML}
`;

const HTML_CONTENT_TYPE = "text/html";

@Hidden()
@Route("site")
export class SiteController extends Controller {
  @Get()
  public getStartPage(): any {
    this.setHeader("content-type", HTML_CONTENT_TYPE);
    return START_HTML;
  }

  @Get("polls/create")
  public getPollsCreatePage(): any {
    this.setHeader("content-type", HTML_CONTENT_TYPE);
    return CREATE_POLLS_HTML;
  }

  @Get("opinions/submit")
  public getOpinionsSubmitPage(): any {
    this.setHeader("content-type", HTML_CONTENT_TYPE);
    return SUBMIT_OPINIONS_HTML;
  }

  @Get("view")
  public getViewPage(): any {
    this.setHeader("content-type", HTML_CONTENT_TYPE);
    return VIEW_HTML;
  }
}
