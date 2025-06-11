import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Shield, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { toast } from 'sonner'
import { useAuth } from '../contexts/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

const loginSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
})

type LoginForm = z.infer<typeof loginSchema>

export default function LoginPage() {
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const { login } = useAuth()

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
  })

  const onSubmit = async (data: LoginForm) => {
    setIsLoading(true)
    try {
      await login(data.username, data.password)
      toast.success('Login successful!')
    } catch (error: any) {
      toast.error(error.message || 'Login failed')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-blue-900 flex items-center justify-center px-4">
      <div className="max-w-md w-full space-y-8">
        {/* Header */}
        <div className="text-center">
          <div className="flex justify-center">
            <div className="p-3 bg-blue-600 rounded-full">
              <Shield className="h-12 w-12 text-white" />
            </div>
          </div>
          <h2 className="mt-6 text-3xl font-bold text-white">
            Welcome to SecureFlow
          </h2>
          <p className="mt-2 text-sm text-gray-400">
            AI-driven security analysis platform
          </p>
        </div>

        {/* Default credentials notice */}
        <div className="bg-blue-900/50 border border-blue-600 rounded-lg p-4">
          <div className="flex items-start space-x-2">
            <AlertCircle className="h-5 w-5 text-blue-400 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-medium text-blue-100">Default Credentials</h3>
              <p className="text-xs text-blue-200 mt-1">
                Username: <code className="bg-blue-800 px-1 rounded">admin</code><br />
                Password: <code className="bg-blue-800 px-1 rounded">admin123</code>
              </p>
              <p className="text-xs text-blue-300 mt-2">
                Please change these credentials in production!
              </p>
            </div>
          </div>
        </div>

        {/* Login form */}
        <form className="mt-8 space-y-6" onSubmit={handleSubmit(onSubmit)}>
          <div className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-300">
                Username
              </label>
              <input
                {...register('username')}
                type="text"
                autoComplete="username"
                className="input mt-1"
                placeholder="Enter your username"
              />
              {errors.username && (
                <p className="mt-1 text-sm text-red-400">{errors.username.message}</p>
              )}
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-300">
                Password
              </label>
              <div className="mt-1 relative">
                <input
                  {...register('password')}
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  className="input pr-10"
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4 text-gray-400" />
                  ) : (
                    <Eye className="h-4 w-4 text-gray-400" />
                  )}
                </button>
              </div>
              {errors.password && (
                <p className="mt-1 text-sm text-red-400">{errors.password.message}</p>
              )}
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="btn btn-primary w-full btn-lg relative"
          >
            {isLoading ? (
              <>
                <LoadingSpinner size="small" className="mr-2" />
                Signing in...
              </>
            ) : (
              'Sign in'
            )}
          </button>
        </form>

        {/* Footer */}
        <div className="text-center text-xs text-gray-500">
          <p>SecureFlow Security Analysis Platform</p>
          <p className="mt-1">Powered by AI • Built for Security Professionals</p>
        </div>
      </div>
    </div>
  )
}