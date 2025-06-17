# gRPC API

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](https://github.com/Concordium/.github/blob/main/.github/CODE_OF_CONDUCT.md)

This repository keeps the gRPC protocol definition file and related documentation on the gRPC interface exposed by concordium-node.

The V2 API consists of three services

- [health.proto](./v2/concordium/health.proto)
- [grpc-health.proto](./grpc/health/v1/health.proto)
- [service.proto](./v2/concordium/service.proto)

and an auxiliary file with all the types for requests and responses

- [types.proto](./v2/concordium/types.proto)

The two health services exist to expose a different API. The first health service returns status via grpc status codes. The second health service is a standard Google health service that communicates service health via response values.

The rendered documentation for the V2 API is available at
http://developer.concordium.software/concordium-grpc-api/

**Generated Code & Compilation Requirements**

To generate the gRPC and Protobuf stubs, you need to use protoc, the Protocol Buffers compiler. Below are the steps and requirements to compile the .proto files.

**Dependencies**

protoc version 28.3 is recommended. This version provides full support for handling optional fields in proto3 and ensures compatibility with all recent features of Protocol Buffers.

**Compilation Example**

Use the following command to generate the gRPC files for different languages:

`protoc --proto_path=concordium_protos \
       --<language>_out=concordium_protos/generated \
       --grpc_out=concordium_protos/generated \
       --experimental_allow_proto3_optional \
       concordium_protos/*.proto`

- Replace <language> with the desired target language (e.g., cpp, java, python, go, php, js, etc.).
- Replace paths as needed.
- Ensure all .proto files are in the appropriate folder.

**Useful References**

- [gRPC GitHub Repository](https://github.com/grpc/grpc): The official gRPC repository contains source code, documentation, and examples for using gRPC across different languages, making it a valuable resource for understanding and implementing gRPC services.

- [Protocol Buffers Documentation](https://protobuf.dev/): This reference documentation is essential for understanding the syntax, features, and capabilities of Protocol Buffers, including how to define messages and services in .proto files.

- [Protocol Buffers Third-Party Plugins](https://github.com/protocolbuffers/protobuf/blob/main/docs/third_party.md): This page provides information on third-party plugins available for use with Protocol Buffers, which can help in generating code for various languages and platforms beyond the official support.

**Notes from Experience**

- Make sure you are using the correct version of protoc. Older versions may have limitations when handling proto3 optional fields, leading to compilation issues.
- If compilation errors occur related to optional fields, upgrading protoc to version 28.3 should resolve these issues.
- The generated files should include both the gRPC client/service stubs and the data classes defined in types.proto.
- If protoc is not compiling the appropriate files, 3rd party plugins may be the solution depending on case, older versions of protoc had more dependencies on plugins.
