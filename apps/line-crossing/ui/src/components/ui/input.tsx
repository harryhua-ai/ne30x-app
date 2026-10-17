import * as React from "react"
import { forwardRef } from "react"
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from "@/lib/utils"

const inputVariants = cva(
  "file:text-foreground placeholder:text-muted-foreground selection:bg-neutral selection:text-neutral-foreground flex h-9 w-full min-w-0 rounded-md border px-3 py-1 text-base shadow-xs transition-[color,box-shadow] outline-none file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm",
  {
    variants: {
      variant: {
        default: "bg-gray-100 border-input focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[1px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:bg-input/30",
        ghost: "bg-transparent border-0 !shadow-none !outline-none focus:!outline-none focus:!ring-0 focus:!ring-offset-0 focus:!shadow-none focus:!border-transparent focus-visible:!outline-none focus-visible:!ring-0 focus-visible:!ring-offset-0 text-right",
        outline: "bg-transparent border-0 !shadow-none rounded-none border-b border-gray-300 !shadow-none !outline-none focus:!ring-0 focus:!ring-offset-0 focus:!shadow-none focus:border-b-2 focus-visible:!outline-none focus-visible:!ring-0 focus-visible:!ring-offset-0 transition-colors",
      },
      inputSize: {
        default: "h-9 px-3 py-1",
        sm: "h-8 px-2 py-1 text-sm",
        lg: "h-10 px-4 py-2",
      },
    },
    defaultVariants: {
      variant: "default",
      inputSize: "default",
    },
  }
)

export interface InputProps
  extends Omit<React.ComponentProps<"input">, "size">,
    VariantProps<typeof inputVariants> {}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, variant, inputSize, ...props }, ref) => (
    <input
      type={type}
      data-slot="input"
      className={cn(inputVariants({ variant, inputSize, className }))}
      ref={ref}
      {...props}
    />
  )
)

Input.displayName = "Input"

export { Input }
