import { cn } from '../utils/cn'

interface ProgressBarProps {
  value: number
  max?: number
  className?: string
  showPercentage?: boolean
}

export default function ProgressBar({ 
  value, 
  max = 100, 
  className,
  showPercentage = false 
}: ProgressBarProps) {
  const percentage = Math.min((value / max) * 100, 100)

  return (
    <div className={cn('space-y-2', className)}>
      {showPercentage && (
        <div className="flex justify-between text-sm text-gray-400">
          <span>Progress</span>
          <span>{Math.round(percentage)}%</span>
        </div>
      )}
      <div className="progress">
        <div 
          className="progress-bar"
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  )
}