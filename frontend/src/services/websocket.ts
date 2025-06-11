import { ProgressUpdate } from '../types'

type ProgressCallback = (progress: ProgressUpdate) => void
type ErrorCallback = (error: Event) => void
type CloseCallback = (event: CloseEvent) => void

class WebSocketService {
  private ws: WebSocket | null = null
  private jobId: string | null = null
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectInterval = 1000
  private progressCallback: ProgressCallback | null = null
  private errorCallback: ErrorCallback | null = null
  private closeCallback: CloseCallback | null = null

  connect(
    jobId: string,
    onProgress: ProgressCallback,
    onError?: ErrorCallback,
    onClose?: CloseCallback
  ) {
    this.jobId = jobId
    this.progressCallback = onProgress
    this.errorCallback = onError || null
    this.closeCallback = onClose || null
    this.createConnection()
  }

  private createConnection() {
    if (!this.jobId) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/ws/${this.jobId}`

    try {
      this.ws = new WebSocket(wsUrl)

      this.ws.onopen = () => {
        console.log(`WebSocket connected for job ${this.jobId}`)
        this.reconnectAttempts = 0
      }

      this.ws.onmessage = (event) => {
        try {
          if (event.data.startsWith('pong:')) {
            // Handle ping/pong
            return
          }

          const progress: ProgressUpdate = JSON.parse(event.data)
          this.progressCallback?.(progress)
        } catch (error) {
          console.error('Error parsing WebSocket message:', error)
        }
      }

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error)
        this.errorCallback?.(error)
      }

      this.ws.onclose = (event) => {
        console.log('WebSocket closed:', event.code, event.reason)
        this.closeCallback?.(event)

        // Attempt to reconnect if not intentionally closed
        if (event.code !== 1000 && this.reconnectAttempts < this.maxReconnectAttempts) {
          this.scheduleReconnect()
        }
      }
    } catch (error) {
      console.error('Error creating WebSocket connection:', error)
      this.errorCallback?.(error as Event)
    }
  }

  private scheduleReconnect() {
    this.reconnectAttempts++
    const delay = this.reconnectInterval * Math.pow(2, this.reconnectAttempts - 1)
    
    console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`)
    
    setTimeout(() => {
      this.createConnection()
    }, delay)
  }

  sendPing() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(`ping:${Date.now()}`)
    }
  }

  disconnect() {
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect')
      this.ws = null
    }
    this.jobId = null
    this.progressCallback = null
    this.errorCallback = null
    this.closeCallback = null
    this.reconnectAttempts = 0
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  getReadyState(): number | null {
    return this.ws?.readyState ?? null
  }
}

// Export singleton instance
export const websocketService = new WebSocketService()

// Hook for using WebSocket in React components
export function useWebSocket(
  jobId: string | null,
  onProgress: ProgressCallback,
  onError?: ErrorCallback,
  onClose?: CloseCallback
) {
  const connect = () => {
    if (jobId) {
      websocketService.connect(jobId, onProgress, onError, onClose)
    }
  }

  const disconnect = () => {
    websocketService.disconnect()
  }

  const isConnected = () => {
    return websocketService.isConnected()
  }

  return {
    connect,
    disconnect,
    isConnected,
    sendPing: () => websocketService.sendPing()
  }
}
