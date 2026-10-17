import React, { useState, useRef, useEffect } from 'react';

interface SimpleAndroidSwitchProps {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  disabled?: boolean;
  className?: string;
  'aria-label'?: string;
}

const SimpleAndroidSwitch = React.forwardRef<HTMLButtonElement, SimpleAndroidSwitchProps>(
  ({ checked = false, onCheckedChange, disabled = false, className = '', ...props }, ref) => {
    const [isChecked, setIsChecked] = useState(checked);
    const buttonRef = useRef<HTMLButtonElement>(null);


    useEffect(() => {
      if (ref) {
        if (typeof ref === 'function') {
          ref(buttonRef.current);
        } else {
          ref.current = buttonRef.current;
        }
      }
    }, [ref]);


    useEffect(() => {
      setIsChecked(checked);
    }, [checked]);

    const handleClick = () => {
      if (disabled) return;

      const newChecked = !isChecked;
      setIsChecked(newChecked);
      onCheckedChange?.(newChecked);
    };


    const buttonStyle: React.CSSProperties = {
      position: 'relative',
      display: 'inline-flex',
      height: '24px',
      width: '44px',
      cursor: disabled ? 'not-allowed' : 'pointer',
      alignItems: 'center',
      borderRadius: '12px',
      border: '2px solid transparent',
      transition: 'all 200ms ease-in-out',
      backgroundColor: isChecked ? '#f24a00' : '#d1d5db',
      opacity: disabled ? 0.5 : 1,
      outline: 'none',
      ...(props as React.CSSProperties)
    };

    const thumbStyle: React.CSSProperties = {
      pointerEvents: 'none',
      display: 'block',
      height: '20px',
      width: '20px',
      borderRadius: '50%',
      backgroundColor: 'white',
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
      transition: 'transform 200ms ease-in-out',
      transform: isChecked ? 'translateX(20px)' : 'translateX(0px)'
    };

    return (
      <button
        ref={buttonRef}
        type="button"
        role="switch"
        aria-checked={isChecked}
        aria-disabled={disabled}
        disabled={disabled}
        style={buttonStyle}
        className={className}
        onClick={handleClick}
        {...props}
      >
        <span style={thumbStyle} />
      </button>
    );
  }
);

SimpleAndroidSwitch.displayName = 'SimpleAndroidSwitch';

export { SimpleAndroidSwitch };
export default SimpleAndroidSwitch;
