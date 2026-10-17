"use client"

import * as React from "react"
import * as SwitchPrimitives from "@radix-ui/react-switch"
import SimpleAndroidSwitch from "@/components/android-UI/simple-android-switch"
import { DeviceDetector } from "@/components/android-UI/device-detector"

import { cn } from "@/lib/utils"

const Switch = React.forwardRef<
  React.ElementRef<typeof SwitchPrimitives.Root>,
  React.ComponentPropsWithoutRef<typeof SwitchPrimitives.Root>
>(({ className, ...props }, ref) => {

  if (DeviceDetector.isAndroid()) {
    return (
      <SimpleAndroidSwitch
        ref={ref as React.Ref<HTMLButtonElement>}
        className={typeof className === 'string' ? className : undefined}
        checked={typeof props.checked === 'boolean' ? props.checked : false}
        onCheckedChange={props.onCheckedChange}
        disabled={typeof props.disabled === 'boolean' ? props.disabled : false}
        aria-label={typeof props['aria-label'] === 'string' ? props['aria-label'] : undefined}
      />
    );
  }


  return (
    <SwitchPrimitives.Root
      className={cn(
        "peer inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-primary data-[state=unchecked]:bg-input",
        className
      )}
      {...props}
      ref={ref}
    >
      <SwitchPrimitives.Thumb
        className={cn(
          "pointer-events-none block h-5 w-5 rounded-full bg-background shadow-lg ring-0 transition-transform data-[state=checked]:translate-x-5 data-[state=unchecked]:translate-x-0"
        )}
      />
    </SwitchPrimitives.Root>
  );
})

Switch.displayName = SwitchPrimitives.Root.displayName

export { Switch }
