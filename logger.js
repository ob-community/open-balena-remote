const pino = require('pino');

const isDev = process.env.NODE_ENV !== 'production';

module.exports = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: isDev
    ? {
        target: 'pino-pretty',
        options: { colorize: true, translateTime: true },
      }
    : undefined,
});
