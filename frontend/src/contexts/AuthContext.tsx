import React, { createContext, useContext, useEffect, useState } from 'react'
import { apiClient } from '../services/api'

interface User {
  id: number
  username: string
}

interface AuthContextType {
  user: User | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  loading: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: React.ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem('access_token')
    const userData = localStorage.getItem('user_data')
    
    if (token && userData) {
      try {
        const parsedUser = JSON.parse(userData)
        setUser(parsedUser)
        // Set token in API client
        apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`
      } catch (error) {
        // Invalid user data, clear it
        localStorage.removeItem('access_token')
        localStorage.removeItem('user_data')
      }
    }
    
    setLoading(false)
  }, [])

  const login = async (username: string, password: string) => {
    try {
      const response = await apiClient.post('/auth/login', {
        username,
        password
      })

      const { access_token, user_id, username: returnedUsername } = response.data
      
      // Store token and user data
      localStorage.setItem('access_token', access_token)
      const userData = { id: user_id, username: returnedUsername }
      localStorage.setItem('user_data', JSON.stringify(userData))
      
      // Set token in API client
      apiClient.defaults.headers.common['Authorization'] = `Bearer ${access_token}`
      
      setUser(userData)
    } catch (error: any) {
      throw new Error(error.response?.data?.detail || 'Login failed')
    }
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('user_data')
    delete apiClient.defaults.headers.common['Authorization']
    setUser(null)
  }

  const value = {
    user,
    login,
    logout,
    loading
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}