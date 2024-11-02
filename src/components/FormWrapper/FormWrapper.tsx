import { ReactNode, useCallback, useState, useRef } from 'react';
import { FormProvider, useForm, FieldValues, DefaultValues, UseFormProps } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import DOMPurify from 'dompurify';
import { Box, Alert, CircularProgress, Typography } from '@mui/material';
import CryptoJS from 'crypto-js';

// Enhanced security types
interface CSRFConfig {
  token: string;
  headerName?: string;
  cookieName?: string;
}

interface FileValidationError {
  file: string;
  message: string;
}

interface FileConfig {
  maxSize?: number; // in bytes
  allowedTypes?: string[];
  maxFiles?: number;
  scanForMalware?: boolean;
  sanitizeName?: boolean;
}

interface SecurityConfig {
  rateLimit?: {
    maxAttempts: number;
    windowMs: number;
    tokenBucket?: {
      capacity: number;
      refillRate: number;
    };
  };
  encryption?: {
    enabled: boolean;
    sensitiveFields?: string[];
    key?: string;
    algorithm?: 'AES' | 'RSA';
    publicKey?: string; // For RSA
  };
  maxFieldLength?: number;
  maxFormSize?: number;
  sanitization?: {
    enabled: boolean;
    customRules?: Record<string, (value: unknown) => unknown>;
    allowedTags?: string[];
    allowedAttributes?: Record<string, string[]>;
    stripScripts?: boolean;
  };
  files?: FileConfig;
  headers?: {
    xssProtection?: boolean;
    noSniff?: boolean;
    noCache?: boolean;
  };
}

interface FormState {
  isSubmitting: boolean;
  submitCount: number;
  lastSubmitTime?: number;
  errors: string[];
  warnings: string[];
}

interface FormWrapperProps<TFieldValues extends FieldValues> {
  children: ReactNode;
  onSubmit: (data: TFieldValues, token?: string) => Promise<void> | void;
  defaultValues?: DefaultValues<TFieldValues>;
  schema?: z.ZodType<TFieldValues>;
  csrf?: CSRFConfig;
  security?: SecurityConfig;
  className?: string;
  formProps?: UseFormProps<TFieldValues>;
  onError?: (error: Error) => void;
  beforeSubmit?: (data: TFieldValues) => Promise<boolean> | boolean;
  afterSubmit?: (data: TFieldValues) => void;
  loadingComponent?: ReactNode;
}

// File validation utility
const validateFile = (file: File, config: FileConfig): FileValidationError[] => {
  const errors: FileValidationError[] = [];
  
  if (config.maxSize && file.size > config.maxSize) {
    errors.push({
      file: file.name,
      message: `File exceeds maximum size of ${config.maxSize / 1024 / 1024}MB`
    });
  }
  
  if (config.allowedTypes && !config.allowedTypes.includes(file.type)) {
    errors.push({
      file: file.name,
      message: `File type ${file.type} is not allowed`
    });
  }
  
  return errors;
};

// Enhanced sanitization utility
const sanitizeData = <T extends Record<string, unknown>>(
  data: T, 
  config?: SecurityConfig['sanitization']
): T => {
  const sanitizeValue = (value: unknown, fieldName?: string): unknown => {
    if (typeof value === 'string') {
      let cleaned = DOMPurify.sanitize(value, {
        ALLOWED_TAGS: config?.allowedTags || ['b', 'i', 'em', 'strong'],
        ALLOWED_ATTR: config?.allowedAttributes || [],
        FORBID_TAGS: config?.stripScripts ? ['script'] : [],
        FORBID_ATTR: ['onerror', 'onload', 'onclick'],
      });
      
      if (fieldName && config?.customRules?.[fieldName]) {
        cleaned = config.customRules[fieldName](cleaned) as string;
      }
      
      if (config?.maxFieldLength) {
        cleaned = cleaned.slice(0, config.maxFieldLength);
      }
      
      return cleaned;
    }
    
    if (Array.isArray(value)) {
      return value.map(item => sanitizeValue(item));
    }
    
    if (value && typeof value === 'object') {
      return sanitizeObject(value as Record<string, unknown>);
    }
    
    return value;
  };
  
  const sanitizeObject = (obj: Record<string, unknown>): Record<string, unknown> => {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = sanitizeValue(value, key);
    }
    return result;
  };
  
  return sanitizeObject(data) as T;
};

// Enhanced encryption utility
const encryptData = async <T extends Record<string, unknown>>(
  data: T,
  config: SecurityConfig['encryption']
): Promise<T> => {
  if (!config?.enabled || (!config.key && !config.publicKey)) {
    return data;
  }

  const encrypted: Record<string, unknown> = { ...data };
  const fieldsToEncrypt = config.sensitiveFields || Object.keys(encrypted);
  
  const encryptValue = async (value: unknown): Promise<unknown> => {
    if (typeof value !== 'string') return value;
    
    if (config.algorithm === 'RSA' && config.publicKey) {
      try {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(value);
        
        const publicKey = await crypto.subtle.importKey(
          'spki',
          Buffer.from(config.publicKey, 'base64'),
          {
            name: 'RSA-OAEP',
            hash: 'SHA-256',
          },
          true,
          ['encrypt']
        );
        
        const encryptedData = await crypto.subtle.encrypt(
          { name: 'RSA-OAEP' },
          publicKey,
          encodedData
        );
        
        return Buffer.from(encryptedData).toString('base64');
      } catch (error) {
        console.error('RSA encryption failed:', error);
        return value;
      }
    }
    
    // Fallback to AES encryption
    try {
      return config.key 
        ? CryptoJS.AES.encrypt(value, config.key).toString()
        : value;
    } catch (error) {
      console.error('AES encryption failed:', error);
      return value;
    }
  };
  
  for (const field of fieldsToEncrypt) {
    if (encrypted[field]) {
      encrypted[field] = await encryptValue(encrypted[field]);
    }
  }
  
  return encrypted as T;
};

// Token bucket implementation
class TokenBucket {
  private tokens: number;
  private lastRefill: number;
  
  constructor(
    private readonly capacity: number,
    private readonly refillRate: number
  ) {
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  consume(tokens = 1): boolean {
    this.refill();
    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }
    return false;
  }

  private refill(): void {
    const now = Date.now();
    const timePassed = now - this.lastRefill;
    const refill = timePassed * (this.refillRate / 1000);
    this.tokens = Math.min(this.capacity, this.tokens + refill);
    this.lastRefill = now;
  }
}

// Form throttle implementation
class FormThrottle {
  private attempts: number[] = [];
  
  constructor(
    private readonly windowMs: number,
    private readonly maxAttempts: number
  ) {}

  canSubmit(): boolean {
    const now = Date.now();
    this.attempts = this.attempts.filter(time => now - time < this.windowMs);
    return this.attempts.length < this.maxAttempts;
  }

  recordAttempt(): void {
    this.attempts.push(Date.now());
  }
}

const FormWrapper = <TFieldValues extends FieldValues>({
  children,
  onSubmit,
  defaultValues,
  schema,
  csrf,
  security,
  className,
  formProps,
  onError,
  beforeSubmit,
  afterSubmit,
  loadingComponent
}: FormWrapperProps<TFieldValues>): JSX.Element => {
  const methods = useForm<TFieldValues>({
    defaultValues,
    resolver: schema ? zodResolver(schema) : undefined,
    mode: 'onBlur',
    ...formProps
  });

  const [formState, setFormState] = useState<FormState>({
    isSubmitting: false,
    submitCount: 0,
    errors: [],
    warnings: []
  });

  const fileInputRef = useRef<HTMLInputElement>(null);
  
  const [tokenBucket] = useState(() => 
    security?.rateLimit?.tokenBucket 
      ? new TokenBucket(
          security.rateLimit.tokenBucket.capacity,
          security.rateLimit.tokenBucket.refillRate
        )
      : null
  );

  const [throttle] = useState(() =>
    security?.rateLimit
      ? new FormThrottle(
          security.rateLimit.windowMs,
          security.rateLimit.maxAttempts
        )
      : null
  );

  const validateFiles = useCallback((files: FileList | null): FileValidationError[] => {
    if (!files || !security?.files) return [];
    
    const errors: FileValidationError[] = [];
    
    if (security.files.maxFiles && files.length > security.files.maxFiles) {
      errors.push({
        file: 'multiple',
        message: `Maximum ${security.files.maxFiles} files allowed`
      });
      return errors;
    }
    
    for (let i = 0; i < files.length; i++) {
      errors.push(...validateFile(files[i], security.files));
    }
    
    return errors;
  }, [security?.files]);

  const checkRateLimit = useCallback((): boolean => {
    if (!security?.rateLimit) return true;

    if (tokenBucket && !tokenBucket.consume()) {
      return false;
    }

    if (throttle && !throttle.canSubmit()) {
      return false;
    }

    return true;
  }, [security?.rateLimit, tokenBucket, throttle]);

  const handleSubmit = methods.handleSubmit(async (data: TFieldValues) => {
    try {
      setFormState(prev => ({
        ...prev,
        isSubmitting: true,
        errors: [],
        warnings: []
      }));

      // Rate limiting check
      if (!checkRateLimit()) {
        throw new Error('Too many attempts. Please try again later.');
      }
      
      if (throttle) {
        throttle.recordAttempt();
      }

      // File validation
      const files = fileInputRef.current?.files;
      const fileErrors = validateFiles(files);
      if (fileErrors.length > 0) {
        throw new Error(fileErrors.map(e => `${e.file}: ${e.message}`).join('. '));
      }

      // Size check
      if (security?.maxFormSize) {
        const size = new Blob([JSON.stringify(data)]).size;
        if (size > security.maxFormSize) {
          throw new Error('Form data is too large');
        }
      }

      // Pre-submit hook
      if (beforeSubmit) {
        const shouldContinue = await beforeSubmit(data);
        if (!shouldContinue) {
          throw new Error('Form submission cancelled');
        }
      }

      // Process data
      const processedData = security?.sanitization?.enabled 
        ? sanitizeData(data as Record<string, unknown>, security.sanitization)
        : data;

      // Encrypt sensitive data
      const finalData = security?.encryption?.enabled
        ? await encryptData(processedData as Record<string, unknown>, security.encryption)
        : processedData;

      // Submit form
      await onSubmit(finalData as TFieldValues, csrf?.token);
      
      // Post-submit hook
      if (afterSubmit) {
        afterSubmit(finalData as TFieldValues);
      }

      setFormState(prev => ({
        ...prev,
        submitCount: prev.submitCount + 1,
        lastSubmitTime: Date.now()
      }));

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'An error occurred';
      setFormState(prev => ({
        ...prev,
        errors: [...prev.errors, errorMessage]
      }));
      
      if (onError && error instanceof Error) {
        onError(error);
      }
      
      console.error('Form submission error:', error);
    } finally {
      setFormState(prev => ({
        ...prev,
        isSubmitting: false
      }));
    }
  });

  return (
    <FormProvider {...methods}>
      <Box 
        component="form" 
        onSubmit={handleSubmit} 
        className={className} 
        noValidate
        encType="multipart/form-data"
      >
        {formState.errors.length > 0 && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {formState.errors.map((error, index) => (
              <Typography key={index} component="div">
                {error}
              </Typography>
            ))}
          </Alert>
        )}
        
        {formState.warnings.length > 0 && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            {formState.warnings.map((warning, index) => (
              <Typography key={index} component="div">
                {warning}
              </Typography>
            ))}
          </Alert>
        )}

        {csrf?.token && (
          <input 
            type="hidden" 
            name="csrf_token" 
            value={csrf.token}
          />
        )}
        
        <input
          type="file"
          ref={fileInputRef}
          style={{ display: 'none' }}
          multiple={security?.files?.maxFiles !== 1}
          accept={security?.files?.allowedTypes?.join(',')}
          onChange={(e) => {
            const errors = validateFiles(e.target.files);
            if (errors.length > 0) {
              setFormState(prev => ({
                ...prev,
                errors: [...prev.errors, ...errors.map(e => `${e.file}: ${e.message}`)]
              }));
              if (e.target instanceof HTMLInputElement) {
                e.target.value = '';
              }
            }
          }}
        />
        
        {formState.isSubmitting ? (
          loadingComponent || (
            <Box display="flex" justifyContent="center" my={2}>
              <CircularProgress />
            </Box>
          )
        ) : children}
      </Box>
    </FormProvider>
  );
};

export { FormWrapper };
export type { 
  FormWrapperProps, 
  CSRFConfig, 
  SecurityConfig, 
  FileConfig, 
  FormState,
  FileValidationError
};