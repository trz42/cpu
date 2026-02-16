# CPU Logging Guide

## Overview

CPU uses Python's standard logging module with a custom `TRACE` level for comprehensive debugging capabilities.

## Log Levels

### When to Use Each Level

**TRACE (5)** - Deep debugging only
- Function entry/exit (via `@trace_calls` decorator)
- Very detailed operational flow
- Should be disabled in production
- Example: `logger.trace("Entering process_webhook")`

**DEBUG (10)** - Development and troubleshooting
- Detailed diagnostic information
- Variable values at decision points
- Queue sizes, state changes
- Example: `logger.debug(f"Queue size: {queue.qsize()}")`

**INFO (20)** - Normal operations (default)
- Component lifecycle events
- Significant business events
- Default for production
- Example: `logger.info("Component initialized successfully")`

**WARNING (30)** - Attention needed
- Unexpected but handled situations
- Retry attempts
- Degraded operation
- Example: `logger.warning("Retrying failed operation (attempt 2/3)")`

**ERROR (40)** - Failures
- Operation failures
- Component errors
- Exceptions
- Example: `logger.error(f"Failed to process message: {err}")`

**CRITICAL (50)** - System failures
- Unrecoverable errors
- Application shutdown
- Example: `logger.critical("Cannot connect to required service, shutting down")`

## Configuration

### Basic Configuration
```yaml
bot:
  logging:
    level: INFO
    file: logs/cpu.log
    format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_bytes: 10485760  # 10MB
    backup_count: 5
```

### Per-Module Log Levels
```yaml
bot:
  logging:
    level: INFO  # Default
    
    loggers:
      cpu.messaging: DEBUG  # More detail for messaging
      cpu.components: INFO
      cpu.config: WARNING  # Less noise from config
```

### Development vs Production

**Development:**
```yaml
bot:
  logging:
    level: DEBUG
    loggers:
      cpu.messaging.queue_thread: TRACE  # Deep debugging
```

**Production:**
```yaml
bot:
  logging:
    level: INFO  # Less overhead
    # No TRACE in production
```

## Using the trace_calls Decorator

### Basic Usage
```python
from cpu.logging.decorators import trace_calls
from cpu.logging.setup import TRACE

@trace_calls(level=TRACE)
def process_webhook(webhook_data: dict) -> None:
    """Process webhook - entry/exit will be logged at TRACE level."""
    # Implementation
```

### When to Use

**DO use on:**
- Public API methods
- Component lifecycle methods
- Complex business logic
- Methods you frequently debug

**DON'T use on:**
- Methods in tight loops
- Simple getters/setters
- Internal helpers
- Properties

## Best Practices

### DO

✅ Use structured logging with context
```python
logger.info(f"Processing message {msg.id} from {msg.source}")
```

✅ Log state transitions
```python
logger.info(f"Component state: {old_state} → {new_state}")
```

✅ Include error context
```python
logger.error(f"Failed to connect to {host}:{port}: {err}")
```

### DON'T

❌ Log sensitive data
```python
# BAD
logger.debug(f"Token: {api_token}")

# GOOD
logger.debug("Token authentication successful")
```

❌ Log in tight loops
```python
# BAD
for item in large_list:
    logger.debug(f"Processing {item}")  # Too much!

# GOOD
logger.debug(f"Processing {len(large_list)} items")
```

❌ Use print statements
```python
# BAD
print("Starting process")

# GOOD
logger.info("Starting process")
```

## Troubleshooting with Logs

### Finding Issues

1. **Enable DEBUG for specific module:**
```yaml
   loggers:
     cpu.messaging.queue_thread: DEBUG
```

2. **Enable TRACE for deep debugging:**
```yaml
   loggers:
     cpu.components.orchestrator: TRACE
```

3. **Check log files:**
```bash
   tail -f logs/cpu.log
   grep ERROR logs/cpu.log
```

### Common Patterns

**Component won't start:**
```bash
grep "component_name" logs/cpu.log | grep -E "(ERROR|CRITICAL)"
```

**Message not delivered:**
```bash
grep "message_id" logs/cpu.log | grep -E "(WARNING|ERROR)"
```

**Performance issues:**
```bash
# Enable TRACE and look for slow operations
grep "TRACE" logs/cpu.log | grep -E "took|duration"
```

## Performance Impact

- **INFO level**: <1% overhead ✅ Production recommended
- **DEBUG level**: 2-5% overhead ⚠️ Use sparingly in production
- **TRACE level**: 5-10% overhead ❌ Development only

## Examples

See `tests/integration/test_logging_integration.py` for complete examples.
