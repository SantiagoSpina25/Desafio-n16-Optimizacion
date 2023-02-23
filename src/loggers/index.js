import log4js from "log4js";

log4js.configure({
    appenders: {
        myLoggerConsole: { type: "console" },
        myLoggerFileWarn: { type: 'file', filename: './logs/warn.log' },
        myLoggerFileError: { type: 'file', filename: './logs/error.log' }
    },

    categories: {
        default: { appenders: ['myLoggerConsole'], level: 'trace' },
        info: { appenders: ['myLoggerConsole'], level: 'debug' },
        warn: { appenders: ['myLoggerConsole', "myLoggerFileWarn"], level: 'warn' },
        error: { appenders: ['myLoggerConsole', "myLoggerFileError"], level: 'info' }
    }
})

const loggerInfo = log4js.getLogger("info")
const loggerWarn = log4js.getLogger("warn")
const loggerError = log4js.getLogger("error")

export function logInfo(msj){
    loggerInfo.info(msj)
}

export function logWarn(msj){
    loggerWarn.warn(msj)
}

export function logError(msj){
    loggerError.error(msj)
}