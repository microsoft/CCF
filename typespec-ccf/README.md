# Microsoft.mCCF

> see https://aka.ms/autorest

This is the AutoRest configuration file for Microsoft.mCCF governance data-plane.

## Configuration

Default to building latest tag.

```yaml
openapi-type: data-plane
tag: 2023-06-01-preview
```

### Tag: 2023-06-01-preview

These settings apply only when `--tag=2023-06-01-preview` is specified on the command line.

```yaml $(tag) == '2023-06-01-preview'
openapi-type: data-plane
input-file:
  - ../data-plane/Microsoft.ManagedCcf/preview/2023-06-01-preview/openapi.json
```
