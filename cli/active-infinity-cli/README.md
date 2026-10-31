# active-infinity-cli

Production command-line surface for the Active Infinity codec.

```bash
active-infinity-cli conformance run --manifest conformance/manifest.json
active-infinity-cli validate image.ainf
active-infinity-cli hash image.ainf
active-infinity-cli decode image.ainf
active-infinity-cli encode source.active --name app.active
active-infinity-cli store put image.ainf --root .active-store
active-infinity-cli store get <hash> --root .active-store
active-infinity-cli doctor
```

Exit codes: `0` success, `1` validation/verification failure, `2` usage error.
Diagnostics never print secret payloads or raw capability authority.
