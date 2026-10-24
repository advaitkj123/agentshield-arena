import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/50',
  {
    variants: {
      variant: {
        default: 'bg-brand-blue text-white hover:bg-brand-blue/90 shadow-[0_0_20px_-4px_var(--color-brand-blue)]',
        secondary: 'glass text-white hover:bg-white/10',
        ghost: 'text-white/70 hover:text-white hover:bg-white/5',
        destructive: 'bg-brand-red text-white hover:bg-brand-red/90',
        outline: 'border border-white/15 text-white hover:bg-white/5 bg-transparent',
        success: 'bg-brand-green text-black hover:bg-brand-green/90',
      },
      size: {
        default: 'h-10 px-5 rounded-app-sm',
        sm: 'h-8 px-3 text-xs rounded-app-sm',
        lg: 'h-12 px-7 text-base rounded-pill',
        pill: 'h-11 px-6 rounded-pill',
        icon: 'h-9 w-9 rounded-app-sm',
      },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

function Button({ className, variant, size, asChild = false, ...props }: ButtonProps) {
  const Comp = asChild ? Slot : 'button'
  return <Comp className={cn(buttonVariants({ variant, size, className }))} {...props} />
}

export { Button, buttonVariants }
