# sandbox-auth
Authentication Provider Service for Developer Sandbox

## Building

This project requires Goagen to generate artifacts required for the REST endpoints.
Refer to [this page](https://goa.design/implement/goagen/) for installation instructions.

This project requires Podman to build. Refer to the [Podman](https://podman.io/getting-started) getting started guide for installation instructions.

Execute the `build.sh` script to build the Sandbox-Auth container. 

## Testing

Run the tests by executing `test.sh`. This project uses [Testcontainers for Golang](https://golang.testcontainers.org/) which 
allows it to spin up a Postgres database automatically for the purpose of integration tests.