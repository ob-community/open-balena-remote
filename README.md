# Remote Device Access for Open Balena

Remote device access utility for [openbalena](https://github.com/balena-io/open-balena), a platform to deploy and manage
connected devices.

## Dependencies

This project only requires a running instance of `open-balena` to work, however you will need to manually enter
connection strings in the browser. You can also use this as a component of
[open-balena-admin](https://github.com/dcaputo-harmoni/open-balena-admin) which provides a much user interface to
remotely access devices.

## Configuration

This project relies on one environment variable being set _(via Helm, docker-compose, .env file, etc)_:

- `BALENARC_BALENA_URL` - The domain of your `open-balena` instance, i.e. `openbalena.local`
- `COOKIE_SECRET` - The encryption keys used for session cookies. If this env variable is not set, it will be randomly
  generated at startup, which means all sessions will become invalid each time the open-balena-remote service container
  is restarted.

## Installation

Set the required environment variable and run `node open-balena-remote.js` from the main project folder - and you should
be up and running.

## Usage

To use open-balena-remote, initiate a GET request to the `open-balena-remote` server (default port is 10000, can be
configured with `PORT` environment variable)

Query string parameters:

- `service` - "ssh", "vnc", or "tunnel"; if service is "tunnel", optionally include the initial URL path to access a URL
  path in that container (i.e. /app-node-red/nr-admin?service=tunnel)
- `container` - currently only applicable to "ssh" service, specifies which device container to ssh into. Ignored for
  all other services.
- `port` - currently only applicable to "tunnel" service, specifies the host port that the service has made a HTTP/HTTPS
  service available on
- `uuid` - device UUID to access (short form is acceptable)
- `apiKey` - balena API key with permission to access requested device UUID

## Credits

- This project relies on [balena-cli](https://github.com/balena-io/balena-cli) to operate, many thanks to the balena
  team for developing such a useful and versatile tool
