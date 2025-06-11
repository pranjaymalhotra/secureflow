import { useEffect, useRef, useCallback } from 'react'
import { ProgressUpdate } from '../types'

interface UseWebSocketOptions {
  onMessage?: (data: ProgressUpdate) => void
  onError?: (error: Event) => void
  onClose?: (event: CloseEvent) => void
  enabled?: boolean
}

export function useWebSocket(jobId: string | null, options: UseWebSocketOptions = {}) {
  const { onMessage, onError, onClose, enabled = true } = options
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 5

  const connect = useCallback(() => {
    if (!jobId || !enabled) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/ws/${jobId}`

    try {
      wsRef.current = new WebSocket(wsUrl)

      wsRef.current.onopen = () => {
        console.log(`WebSocket connected for job ${jobId}`)
        reconnectAttempts.current = 0
      }

      wsRef.current.onmessage = (event) => {
        try {
          if (event.data.startsWith('pong:')) return
          
          const data: ProgressUpdate = JSON.parse(event.data)
          onMessage?.(data)
        } catch (error) {
          console.error('Error parsing WebSocket message:', error)
        }
      }

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error)
        onError?.(error)
      }

      wsRef.current.onclose = (event) => {
        console.log('WebSocket closed:', event.code, event.reason)
        onClose?.(event)

        // Attempt reconnection if not intentionally closed
        if (event.code !== 1000 && reconnectAttempts.current < maxReconnectAttempts && enabled) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000)
          reconnectAttempts.current++
          
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log(`Reconnecting... (attempt ${reconnectAttempts.current})`)
            connect()
          }, delay)
        }
      }
    } catch (error) {
      console.error('Error creating WebSocket:', error)
      onError?.(error as Event)
    }
  }, [jobId, enabled, onMessage, onError, onClose])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    if (wsRef.current) {
      wsRef.current.close(1000, 'Component unmounted')
      wsRef.current = null
    }
  }, [])

  const sendMessage = useCallback((message: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(message)
    }
  }, [])

  useEffect(() => {
    if (enabled && jobId) {
      connect()
    }

    return () => {
      disconnect()
    }
  }, [connect, disconnect, enabled, jobId])

  return {
    connect,
    disconnect,
    sendMessage,
    isConnected: wsRef.current?.readyState === WebSocket.OPEN
  }
}