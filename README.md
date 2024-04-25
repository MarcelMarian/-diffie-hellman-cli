# Go Diffie-Hellman client
This is an example of a Diffie-Hellman key exchange algorythm. This example implements a gRPC client that exchanges the public key with a server application.  
The server side implementation is in the diffie-hellman-srv repo.
To run this example on a Linux distribution the following step should be followed:
- build both the server and the client containers (see the [Building](#building) section)
- make sure you have the docker-compose or docker stack installed on the host system
- run
```bash
docker-compose up
```

## Signing Tools

The tools required to sign containers with the Code Signing Servive (HSM) are embedded in this repository
as a Git submodule, make sure to run the following command to initialise the submodule before attempting
to sign anything:
```bash
git submodule update --init --recursive
```

## Supported Architectures

The following are supported (the latter two using Go cross compilation):
- `amd64`
- `arm`
- `arm64`

The architecture to build for is selected via the value of the `ARCH` environment varaible.

## Go Modules

The build assumes the use of Go modules (which will be the default for all Go builds as of Go 1.13) and vendoring,
which creates as copy of the correct versions all the required dependencies in source form in the `vendor` directory.
To populate the`vendor` directory run `go mod vendor` from inside a development shell (use `make shell`). If you remove
dependencies run `go mod tidy` to remove modules no longer needed. The Go module mechanism uses two files `go.mod` and
`go.sum` which should be committed each time they change along with the contents of the `vendor` directory.

For more details about Go modules see [here](https://golang.org/ref/mod).

## Building

The build (and other related activities) is acheived via a set of shell scripts found in the `scripts` directory. The
scripts are configured via environment variables all of which have sensible default values (which are shown below). In
the vast majority of cases the values will not require change. To change a value simply export it into the environment
before running the scripts.

To automate the most important part of the build process a simple `Makefile` is provided with `build`, `all-build` and
`clean` targets.

The variables (and their default values are shown below).

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `OS` | The value of GOOS to use | `linux` |
| `ARCH` | The value of GOARCH to use | `amd64` |
| `APPNAME` | The name of the application binary | `diffie-hellman-service` |
| `VERSION` | The semantic version of the application | `1.0.0` |
| `BUILD_IMAGE` | The name of the build container | `diffie-hellman-service-golang:1.16.0-buster` |
| `PROTODIR` | The location of protocol buffer files | `proto` |
| `BASE_IMAGE` | The base of the application container | `scratch` |

The build is performed within a consistent environment defined by a build container. The build container can be created
using the `scripts/buildbuildcontainer` script. This script has an optional `--push` argument which can be used to push
the created build container to a registry.

This script can be further customised via the following variable:

- `BASE_BUILD_IMAGE` = `golang:1.16.0-buster`

### Building the Application

Run `scripts/buildapplication` to build the application.

The shell script `build/build.sh` is used to build the application.

### Testing the Application

Run `scripts/testapplication` to test the application.

The shell script `build/test.sh` is used to test the application.

### Containerising the Application

Run `scripts/buildcontainer` to containerise the application.

### Cleaning Up

Run `scripts/cleanup` to clean up the working directory.

## Using Visual Studio Code

The directory `.devcontainer` contains the files required to use the Remote Containers features of Visual
Studio Code to develop in a container using Visual Studio Code. This has been tested on Windows 10 with
WSL2 and Docker Desktop installed. To use, first open the clonmed directory in WSL2 (Remote Explorer WSL
Targets) and enter the container using the `Remote-Containers: Reopen in Container` command.

