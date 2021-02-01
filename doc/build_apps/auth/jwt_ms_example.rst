JWT Authentication example using Microsoft Identity Platform
------------------------------------------------------------

The `Forum sample app <https://github.com/microsoft/CCF/blob/master/samples/apps/forum>`_ of CCF uses the `Microsoft Identity Platform <https://aka.ms/IdentityPlatform>`_ for user authentication.
In this sample, users submit opinions for polls without other users seeing their opinions.
After a certain number of opinions have been submitted, aggregate statistics can be retrieved.

To get started, `register an application <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app>`_ with the Microsoft Identity Platform.
After registering the app, navigate to "Expose an API" and create a scope named ``Polls.Access``, allowing "Admins and users" to consent.
The name of the scope is used in the JavaScript code of the website client.
Under "Authentication", make sure a "Single-page application" is added with a redirect URL that matches the website.
In the Forum sample the redirect URL is ``https://.../app/site``, and particularly during development it is convenient to add a local URL as well: ``https://127.0.0.1:8000/app/site``.

.. note::

    The Forum sample is technically a combination of a `web API application <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-configure-app-expose-web-apis>`_ (the CCF app) and a `browser client application <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-configure-app-access-web-apis>`_ (the website).
    The latter is also called a single-page application in Microsoft terms.
    For simplicity and because both applications are considered public it is sufficient to register only a single application which will represent both the server and the client.

Open `samples/apps/forum/src/authentication.ts <https://github.com/microsoft/CCF/blob/master/samples/apps/forum/src/authentication.ts>`_ and replace the app ID with the one registered earlier.
This file is responsible for validating incoming JWTs and extracting a user id for associating opinions to users.

The Forum sample can now be run in a local sandbox with:

.. code-block:: bash

    $ cd samples/apps/forum
    $ npm install
    $ npm start

.. note::

    The `start script <https://github.com/microsoft/CCF/blob/master/samples/apps/forum/test/start.ts>`_ automatically downloads the current JWT public signing keys from Microsoft and stores them in the network using the ``--jwt-issuer`` sandbox argument.

Navigate to `<https://127.0.0.1:8000/app/site>`_ and click the Login button.
You will be redirected to the Microsoft Identity Platform for authentication and back to the Forum sample.
After logging in, polls can be created and opinions submitted.

Note that aggregated opinion data is only returned after reaching a certain threshold.
To simulate multiple different users submitting opinions, the `start script <https://github.com/microsoft/CCF/blob/master/samples/apps/forum/test/start.ts>`_ adds an additional fake JWT issuer based on a locally generated private key and certificate.
Run the following scripts to submit opinions of fake users using the fake issuer:

.. code-block:: bash

    $ python3.8 test/demo/generate-opinions.py test/demo/polls.csv 9
    $ npm run ts test/demo/generate-jwts.ts . 9
    $ npm run ts test/demo/submit-opinions.ts .