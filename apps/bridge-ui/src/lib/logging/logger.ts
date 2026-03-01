import { invoke } from '@tauri-apps/api/core'

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

type LogContext = Record<string, unknown> | unknown[] | string | number | boolean | null | undefined

const LOG_LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
}

function normalizeLevel(raw: string | undefined): LogLevel {
  if (!raw) return 'info'
  const value = raw.toLowerCase().trim()
  if (value === 'debug' || value === 'info' || value === 'warn' || value === 'error') {
    return value
  }
  return 'info'
}

function parseBoolean(raw: string | undefined, fallback: boolean): boolean {
  if (raw == null) return fallback
  const value = raw.toLowerCase().trim()
  return value === '1' || value === 'true' || value === 'yes' || value === 'on'
}

const minLevel = normalizeLevel(import.meta.env.VITE_LOG_LEVEL)
const sinkEnabled = parseBoolean(import.meta.env.VITE_LOG_FILE_SINK, true)
let sinkHealthy = sinkEnabled
let sinkWarned = false

function shouldLog(level: LogLevel): boolean {
  return LOG_LEVEL_ORDER[level] >= LOG_LEVEL_ORDER[minLevel]
}

function contextToString(context: LogContext): string | undefined {
  if (context === undefined) return undefined
  if (typeof context === 'string') return context
  try {
    return JSON.stringify(context)
  } catch {
    return String(context)
  }
}

function writeToConsole(level: LogLevel, target: string, message: string, context: LogContext): void {
  const prefix = `[${new Date().toISOString()}] [${level}] [${target}] ${message}`
  if (level === 'debug') {
    console.debug(prefix, context ?? '')
  } else if (level === 'info') {
    console.info(prefix, context ?? '')
  } else if (level === 'warn') {
    console.warn(prefix, context ?? '')
  } else {
    console.error(prefix, context ?? '')
  }
}

async function writeToSink(level: LogLevel, target: string, message: string, context: LogContext): Promise<void> {
  if (!sinkHealthy) return
  const contextString = contextToString(context)
  try {
    await invoke<void>('bridge_frontend_log', {
      level,
      target,
      message,
      context: contextString ?? null,
    })
  } catch (error) {
    if (!sinkWarned) {
      sinkWarned = true
      sinkHealthy = false
      console.warn('[logger] frontend file sink disabled after write error', error)
    }
  }
}

function emit(level: LogLevel, target: string, message: string, context: LogContext = undefined): void {
  if (!shouldLog(level)) return
  writeToConsole(level, target, message, context)
  void writeToSink(level, target, message, context)
}

export const logger = {
  debug(target: string, message: string, context?: LogContext): void {
    emit('debug', target, message, context)
  },
  info(target: string, message: string, context?: LogContext): void {
    emit('info', target, message, context)
  },
  warn(target: string, message: string, context?: LogContext): void {
    emit('warn', target, message, context)
  },
  error(target: string, message: string, context?: LogContext): void {
    emit('error', target, message, context)
  },
}
