import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-medium font-mono-data tracking-wide border',
  {
    variants: {
      variant: {
        default: 'bg-brand-blue/15 text-brand-blue border-brand-blue/30',
        green: 'bg-brand-green/15 text-brand-green border-brand-green/30',
        red: 'bg-brand-red/15 text-brand-red border-brand-red/30',
        orange: 'bg-brand-orange/15 text-brand-orange border-brand-orange/30',
        purple: 'bg-brand-purple/15 text-brand-purple border-brand-purple/30',
        cyan: 'bg-brand-cyan/15 text-brand-cyan border-brand-cyan/30',
        muted: 'bg-white/5 text-white/60 border-white/10',
      },
    },
    defaultVariants: { variant: 'default' },
  },
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant, className }))} {...props} />
}

export { Badge, badgeVariants }
