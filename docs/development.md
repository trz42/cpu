## Debugging with Logs

### Enable TRACE for a Module

Edit `config.yaml`:

```yaml
bot:
  logging:
    loggers:
      cpu.messaging: TRACE  # See all messaging details
```

### Run with Debug Logging

```bash
CPU_BOT__LOGGING__LEVEL=DEBUG python -m cpu
```

### View Live Logs

```bash
tail -f logs/cpu.log
```
