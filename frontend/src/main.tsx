import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'sonner'

import App from './App.tsx'
import './index.css'
import { AuthProvider } from './contexts/AuthContext'

// Create a client with better defaults
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      refetchInterval: false, // Disable global polling
      refetchOnWindowFocus: false, // Don't refetch on window focus
      refetchOnReconnect: true, // Only refetch on reconnect
      retry: (failureCount, error: any) => {
        if (error?.response?.status === 401 || error?.response?.status === 403) {
          return false
        }
        return failureCount < 3
      }
    },
    mutations: {
      retry: false
    }
  }
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <App />
          <Toaster 
            position="top-right"
            toastOptions={{
              duration: 4000,
              style: {
                background: '#1f2937',
                color: '#f9fafb',
                border: '1px solid #374151'
              }
            }}
          />
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)


