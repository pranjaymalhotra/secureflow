import { cn } from '../utils/cn'

interface BadgeProps {
  children: React.ReactNode
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'default'
  className?: string
}

export default function Badge({ children, variant = 'default', className }: BadgeProps) {
  const variants = {
    critical: 'badge-critical',
    high: 'badge-high', 
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
    default: 'badge'
  }

  return (
    <span className={cn(variants[variant], className)}>
      {children}
    </span>
  )
}