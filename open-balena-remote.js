// TO DO: replace balena-cli with direct https proxy

const express = require('express');
const URLSearchParams = require('url').URLSearchParams;
const cookieParser = require('cookie-parser');
const { spawn, execSync } = require('child_process');
const { createProxyMiddleware } = require('http-proxy-middleware');
const portfinder = require('portfinder');
const schedule = require('node-schedule');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const util = require('util');
const uuid = require('uuid');
const waitPort = require('wait-port');
const crypto = require('crypto');
const fs = require('fs');
const logger = require('./logger.js');
require('dotenv').config();

const DEBUG = false;

// port and host that base instance listens on
const PORT = 10000;
const HOST = '0.0.0.0';
const START_PROXY_PORT = 10001;
const END_PROXY_PORT = 10009;
const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_PREFIX = 'remote.';
const ERROR_PATH = '/error.html';

const routes = {
  tunnel: {
    route: 'protocol://127.0.0.1:tunnel',
  },
  vnc: {
    remotePort: 5900,
    serverCmd: '/usr/local/bin/websockify --web /usr/share/novnc_root localPort 127.0.0.1:tunnelPort',
    serverPath: '/novnc/vnc.html?autoconnect=true&reconnect=true&reconnect_delay=10',
    route: 'http://127.0.0.1:server',
  },
  ssh: {
    remotePort: 22222,
    serverPath: '/ttyd/?arg=port&arg=uuid&arg=container&arg=username&arg=sessionDir',
    route: 'http://127.0.0.1:7681',
  },
};

const loginCmd = '/usr/bin/balena login --token apiKey';
const tunnelCmd = '/usr/bin/balena tunnel uuid -p remotePort:127.0.0.1:localPort';
const killCmd = 'kill -9 pid';

const sessionStore = new MemoryStore({
  checkPeriod: 24 * 60 * 60 * 1000, // prune expired sessions every 24h (TODO: find a way to have this trigger cleanup just incase)
});
const sessionStoreAll = util.promisify(sessionStore.all.bind(sessionStore));
const sessionStoreSet = util.promisify(sessionStore.set.bind(sessionStore));
const sessionStoreGet = util.promisify(sessionStore.get.bind(sessionStore));
const sessionStoreDestroy = util.promisify(sessionStore.destroy.bind(sessionStore));

const sessionParams = {
  secret: COOKIE_SECRET,
  saveUninitialized: false,
  cookie: {
    path: '/',
    httpOnly: true,
    secure: process.env.HOST_MODE === 'secure',
    sameSite: 'None',
    signed: true,
    maxAge: 6 * 60 * 60 * 1000,
  }, // six hour session max 6 * 60 * 60 * 1000
  resave: false,
  store: sessionStore,
  unset: 'destroy',
};

var expressServers = {};
var scheduledCleanups = {};

// On initial call, open VPN tunnel to device, start server if necessary, set session variables and redirect
async function initialRequestHandler(req, res, next) {
  switch (req._parsedUrl.pathname) {
    case '/endSession':
      if (req.query.sessionID && (await sessionStoreGet(req.query.sessionID))) {
        logger.debug({ sessionID: req.query.sessionID }, 'Received request to delete session');
        cleanupSession.bind({ sessionID: req.query.sessionID })();
        res.sendStatus(200).end();
      }
      break;
    default:
      if (routes[req.query.service]) {
        try {
          // create new session in session store
          var sessionID = await startSession();
          // set active service
          var sessionData = { activeService: req.query.service };
          await updateSession(sessionID, sessionData);
          // determine proxy port to use
          sessionData.proxyPort = await getProxyPort(req.signedCookies);
          logger.debug({ proxyPort: sessionData.proxyPort }, 'Setting proxy port');
          await updateSession(sessionID, sessionData);
          // create unique session directory to hold balena token for this session
          sessionData.sessionDir = '/tmp/' + uuid.v1();
          if (!fs.existsSync(sessionData.sessionDir)) {
            fs.mkdirSync(sessionData.sessionDir);
          }
          if (!req.query.jwt && !req.query.apiKey) {
            throw 'At least one of jwt or apiKey must be specified';
          }
          if (req.query.jwt) {
            // save provided JWT to session folder
            fs.writeFileSync(`${sessionData.sessionDir}/token`, req.query.jwt);
          } else {
            // otherwise log in to openbalena using apiKey to get jwt
            await executeCommand(
              loginCmd,
              {
                apiKey: req.query.apiKey,
              },
              { BALENARC_DATA_DIRECTORY: sessionData.sessionDir },
              false,
            );
          }
          // get remote port
          var remotePort = routes[req.query.service].remotePort ? routes[req.query.service].remotePort : req.query.port;
          if (!remotePort) {
            throw 'Port must be provided to tunnel';
          }
          // open vpn tunnel via balena-cli
          sessionData.tunnel = { port: await portfinder.getPortPromise({ port: 20000, stopPort: 29999 }) };
          sessionData.tunnel.pid = await executeCommand(
            tunnelCmd,
            {
              uuid: req.query.uuid,
              remotePort: remotePort,
              localPort: sessionData.tunnel.port,
              tunnelID: sessionData.tunnel.id,
            },
            { BALENARC_DATA_DIRECTORY: sessionData.sessionDir },
            true,
          );
          await updateSession(sessionID, sessionData);
          var portOpen = await waitPort({ host: '127.0.0.1', port: sessionData.tunnel.port, timeout: 10 * 1000 });
          if (!portOpen) {
            throw 'Unable to open VPN tunnel';
          }
          logger.debug(
            {
              localPort: sessionData.tunnel.port,
              remoteUUID: req.query.uuid,
              remotePort,
              pid: sessionData.tunnel.pid,
            },
            'Opened VPN tunnel to remote device',
          );
          var redirect = req.protocol + '://' + req.headers.host.split(':')[0] + ':' + sessionData.proxyPort;
          // if necessary to start custom server to faciltate request, do so
          if (routes[req.query.service].serverCmd) {
            sessionData.server = { port: await portfinder.getPortPromise({ port: 30000, stopPort: 39999 }) };
            sessionData.server.pid = await executeCommand(
              routes[req.query.service].serverCmd,
              {
                localPort: sessionData.server.port,
                remotePort: remotePort,
                tunnelPort: sessionData.tunnel.port,
              },
              {},
              true,
            );
            await updateSession(sessionID, sessionData);
            portOpen = await waitPort({ host: '127.0.0.1', port: sessionData.server.port, timeout: 10 * 1000 });
            if (!portOpen) {
              throw 'Unable to start server';
            }
            logger.debug(
              sessionData.server.port === ''
                ? 'No server was started as this is a proxy request only'
                : { port: sessionData.server.port, pid: sessionData.server.pid, msg: 'Started server at 127.0.0.1' },
            );
          }
          // if routing via server instead of directly to target, generate route path using serverPath
          if (routes[req.query.service].serverPath) {
            redirect += routes[req.query.service].serverPath.replace(
              /port|uuid|container|username|sessionDir/gi,
              function (matched) {
                // replace port with server port first (if specified), then tunnel port if no server
                return (
                  (req.query[matched]
                    ? encodeURIComponent(req.query[matched])
                    : sessionData.server
                      ? sessionData.server[matched]
                      : sessionData.tunnel[matched]) ||
                  sessionData[matched] ||
                  ''
                );
              },
            );
            // save private key to session directory if provided
            if (req.query.privateKey) {
              fs.writeFileSync(`${sessionData.sessionDir}/privateKey`, req.query.privateKey);
              fs.chmodSync(`${sessionData.sessionDir}/privateKey`, '0600');
            }
            // otherwise just pass on path based on url provided with initial request to remote
          } else {
            // save protocol (if provided) in session
            if (req.query.protocol) {
              sessionData.protocol = req.query.protocol;
              await updateSession(sessionID, sessionData);
            }
            ['service', 'apiKey', 'uuid', 'container', 'port', 'protocol'].forEach((item) => delete req.query[item]);
            redirect += req._parsedUrl.pathname + '?' + new URLSearchParams(req.query).toString();
          }
          var cookieParams = sessionParams.cookie;
          // override cookie / session expiry if ttlSecs provided
          if (req.query.ttlSecs) {
            cookieParams.maxAge = parseInt(req.query.ttlSecs) * 1000;
          }
          // set cookie with new session ID
          res.cookie(COOKIE_PREFIX + sessionData.proxyPort, sessionID, cookieParams);
          // schedule cleanup of session
          var scheduledCleanupDate = new Date(new Date().getTime() + cookieParams.maxAge).toISOString();
          logger.debug({ scheduledCleanupDate }, 'Scheduling session cleanup');
          scheduledCleanups[sessionID] = schedule.scheduleJob(
            scheduledCleanupDate,
            cleanupSession.bind({ sessionID: sessionID }),
          );
          // finally, redirect!
          logger.debug({ redirect }, 'Redirecting to path');
          res.render('iframe', { iframe_source: redirect, sessionID: sessionID });
        } catch (err) {
          // pass error to error response handler downstream
          next(err);
        }
      } else {
        next();
      }
  }
}

const proxyMiddlewareConfig = {
  target: '',
  changeOrigin: true,
  secure: false,
  ws: true,
  router: async (req) => {
    logger.debug(
      {
        protocol: req.protocol || 'ws',
        host: req.headers['host'] || req.headers['Host'] || 'no-host', // NOTE: node normalizes the header to lowercase, but leaving this as original...
        service: req.session.data.activeService,
        url: req.url,
      },
      'Received proxy request',
    );

    // if no session tied to request (websocket), get session data from memorystore using http headers
    if (!req.session) {
      req.session = { data: await getSessionData(req.rawHeaders) };
    }
    if (!req.session.data) {
      if (req.protocol) {
        throw 'Proxy called without a valid session';
      } else {
        // if no session, return origin or host header as default origin
        const originIndex = [req.rawHeaders.indexOf('origin'), req.rawHeaders.indexOf('Origin')].find((i) => i !== -1);
        const hostIndex = [req.rawHeaders.indexOf('host'), req.rawHeaders.indexOf('Host')].find((i) => i !== -1);
        // if no origin or host header, return default origin to avoid unhandled exception
        return req.rawHeaders[originIndex + 1] ?? `http://${req.rawHeaders[hostIndex + 1] ?? 'no-origin.com'}`;
      }
    }
    logger.debug({ sessionData: req.session.data }, 'Proxy called with session data loaded');
    var route = routes[req.session.data.activeService].route;
    // include protocol as needed
    route = route.replace(/protocol/gi, (matched) => {
      return req.session.data[matched];
    });
    // include tunnel or server port as needed
    route = route.replace(/tunnel|server/gi, (matched) => {
      return req.session.data[matched] ? req.session.data[matched].port : '';
    });
    // finally, route!
    logger.debug({ route }, 'Proxying request to server');
    return route;
  },
  on: {
    proxyReqWs: (proxyReq, req, _socket, _options, _head) => {
      if (!req.session.data) {
        // downgrade to HTTP request to be subsequently killed
        proxyReq.path = '';
        proxyReq.removeHeader('Upgrade');
        proxyReq.setHeader('Connection', 'close');
      }
    },
  },
};

async function errorResponseHandler(err, _req, res, _next) {
  logger.error({ err }, 'Unhandled error in request');
  res.render('iframe', { iframe_source: ERROR_PATH, sessionID: '' });
}

// Helper function to execute command and return port and PID (returned from shell script)
async function executeCommand(cmd, params, envs, background) {
  // replace variables in command using keys from params
  var re = new RegExp(Object.keys(params).join('|'), 'g');
  cmd = cmd.replace(re, (match) => params[match]);
  logger.debug({ cmd }, 'Executing command');
  // if executing in background, run as spawn to return child process with pid
  if (background) {
    var child = spawn(cmd.split(' ')[0], cmd.split(' ').slice(1), { env: { ...process.env, ...envs } });
    if (DEBUG) {
      child.stdout.on('data', (data) => {
        logger.debug('stdout: ' + data.toString());
      });
      child.stderr.on('data', (data) => {
        logger.debug('stderr: ' + data.toString());
      });
    }
    child.on('close', cleanupPid.bind(child));
    return child.pid;
    // if executing in foreground, run as execSync
  } else {
    var result = execSync(cmd, { env: { ...process.env, ...envs } });
    logger.debug(result.toString('utf8'));
  }
}

// Helper function to get session data from request headers (needed for websocket connections)
async function getSessionData(reqHeaders) {
  var cookies = {};
  var cookieHeaderIdx =
    reqHeaders.indexOf('cookie') !== -1 ? reqHeaders.indexOf('cookie') : reqHeaders.indexOf('Cookie');
  decodeURIComponent(reqHeaders[cookieHeaderIdx + 1])
    .split(';')
    .forEach(function (cookie) {
      var parts = cookie.match(/(.*?)=(.*)$/);
      if (parts) {
        cookies[parts[1].trim()] = (parts[2] || '').trim();
      }
    });
  // parse port from headers
  var hostHeaderIdx = reqHeaders.indexOf('host') !== -1 ? reqHeaders.indexOf('host') : reqHeaders.indexOf('Host');
  var host = reqHeaders[hostHeaderIdx + 1];
  var port = host.includes(':') ? host.split(':')[1] : PORT;
  // decrypt cookie being used by current server into session ID
  var sessionID = cookieParser.signedCookie(cookies[COOKIE_PREFIX + port], sessionParams.secret);
  // load session data from memory store
  logger.debug({ sessionID }, 'Decoding memory store from websocket request');
  var session = await sessionStoreGet(sessionID);
  if (session) {
    return session.data;
  } else {
    return null;
  }
}

// Helper function to get next proxy port
async function getProxyPort(cookies) {
  var cookiesArr = [];
  // get port # and expiry date for each currently used cookie (session)
  for (cookieName of Object.keys(cookies)) {
    var port = cookieName.split('.')[1];
    var session = await sessionStoreGet(cookies[cookieName]);
    if (session) {
      cookiesArr.push({
        sessionID: cookies[cookieName],
        port: parseInt(port),
        expires: new Date(session.cookie.expires),
      });
    }
  }
  logger.debug({ sessions: cookiesArr }, 'Finding next available port using detected active sessions');
  // always use base port if available, otherwise remove it from the list
  if (!cookiesArr.find((x) => x.port === PORT)) {
    return PORT;
  } else {
    cookiesArr = cookiesArr.filter((x) => x.port !== PORT);
  }
  // otherwise find lowest open port in range
  for (var i = START_PROXY_PORT; i <= END_PROXY_PORT; i++) {
    if (!cookiesArr.find((x) => x.port === i)) {
      return i;
    }
  }
  // otherwise find the soonest expiring port, kill old session and reuse it
  cookiesArr.sort((a, b) => a.expires - b.expires);
  cleanupSession.bind({ sessionID: cookiesArr[0].sessionID })();
  return cookiesArr[0].port;
}

// Helper function to manually start a session and save it in memorystore
async function startSession() {
  // generate sessionID
  var sessionID = uuid.v1();
  var newCookie = JSON.parse(JSON.stringify(sessionParams.cookie));
  // populate originalMaxAge and expires which are needed by memorystore, remove maxAge
  newCookie.originalMaxAge = newCookie.maxAge;
  newCookie.expires = new Date(new Date().getTime() + sessionParams.cookie.maxAge).toISOString();
  delete newCookie.maxAge;
  // save session in memorystore
  await sessionStoreSet(sessionID, { cookie: newCookie, data: {} });
  return sessionID;
}

// Helper function to update a session in memorystore
async function updateSession(sessionID, sessionData) {
  var session = await sessionStoreGet(sessionID);
  session.data = sessionData;
  await sessionStoreSet(sessionID, session);
}

// Helper function to start a new express / proxy server
async function startProxy(proxyPort, initialHandler) {
  var newApp = express();
  var proxySessionParams = sessionParams;
  // set appropriate prefix for session cookie based on port
  proxySessionParams.name = COOKIE_PREFIX + proxyPort;
  newApp.set('trust proxy', 1);
  newApp.set('view engine', 'pug');
  newApp.use(session(proxySessionParams));
  newApp.use(cookieParser(COOKIE_SECRET));
  newApp.use(express.static('html'));
  // only include initial request handler in base instance
  if (initialHandler === true) {
    newApp.use(initialRequestHandler);
  }
  newApp.use(createProxyMiddleware(proxyMiddlewareConfig));
  newApp.use(errorResponseHandler);

  var newServer = newApp.listen(proxyPort, HOST, () => {
    // add server to global object to allow subsequent access
    expressServers[newServer.address().port] = newServer;
  });
  // wait for proxy server to come online
  await waitPort({ host: '127.0.0.1', port: proxyPort });
}

// Helper function to cleanup when PID is terminated
async function cleanupPid() {
  try {
    logger.debug({ pid: this.pid }, 'Cleaning up after termination of PID');
    var sessions = await sessionStoreAll();
    logger.debug({ sessions }, 'Found open sessions');
    Object.keys(sessions).forEach((sessionID) => {
      var sessionData = sessions[sessionID].data;
      if (
        sessionData &&
        ((sessionData.tunnel && sessionData.tunnel.pid === this.pid) ||
          (sessionData.server && sessionData.server.pid === this.pid))
      ) {
        cleanupSession.bind({ sessionID: sessionID })();
      }
    });
  } catch (error) {
    logger.error({ err: error }, 'Caught error while cleaning up PID');
  }
}

// Helper function to cleanup when session is terminated
async function cleanupSession() {
  try {
    logger.debug({ sessionID: this.sessionID }, 'Cleaning up session');
    var session = await sessionStoreGet(this.sessionID);
    if (session) {
      var sessionData = session.data;
      // kill tunnel and server processes; ignore errors on killing (aready killed)
      try {
        await executeCommand(killCmd, { pid: sessionData.tunnel.pid }, {}, false);
      } catch {}
      if (sessionData.server) {
        try {
          await executeCommand(killCmd, { pid: sessionData.server.pid }, {}, false);
        } catch {}
      }
      // remove session folder
      fs.rmSync(sessionData.sessionDir, { recursive: true, force: true });
      // remove session data from memory store
      logger.debug('Destroying session in memory store');
      await sessionStoreDestroy(this.sessionID);
      // cancel and remove shceduled cleanup object because it is complete
      if (scheduledCleanups[this.sessionID]) {
        scheduledCleanups[this.sessionID].cancel();
        delete scheduledCleanups[this.sessionID];
      }
    } else {
      logger.debug({ sessionID: this.sessionID }, 'Session does not exist');
    }
  } catch (error) {
    logger.error({ err: error }, 'Caught error while cleaning up session');
  }
}

startProxy(PORT, true);
var i = START_PROXY_PORT;
while (i <= END_PROXY_PORT) {
  startProxy(i++, false);
}

// handle possible memory leak per https://github.com/nodejs/node/issues/42154
process.on('uncaughtException', (error, origin) => {
  if (error?.code === 'ECONNRESET') {
    return;
  }
  logger.fatal({ err: error, origin }, 'Uncaught exception');
  process.exit(1);
});
