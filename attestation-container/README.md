# Attestation Container

## development

### Update protobuf

```bash
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative protobuf/attestation-container.proto
```
