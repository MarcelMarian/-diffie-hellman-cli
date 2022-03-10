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
| `REGISTRY` | The Docker Trusted Registry to push and pull to/from | `registry.gear.ge.com/csp` |
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

### Pushing the Application Container

Run `scripts/pushcontainer` to push the containerised application to a registry.

- You may need to authenticate with the registry for this to complete without error.

### Packaging the Application

Run `scripts/packageapplication` to package the containerised application for Predix Edge OS deployment.

### Signing the Packaged Application

Run `scripts/signpackage` to sign the packaged application for deployment on production builds of Predix Edge OS.

### Cleaning Up

Run `scripts/cleanup` to clean up the working directory.

## Using Visual Studio Code

The directory `.devcontainer` contains the files required to use the Remote Containers features of Visual
Studio Code to develop in a container using Visual Studio Code. This has been tested on Windows 10 with
WSL2 and Docker Desktop installed. To use, first open the clonmed directory in WSL2 (Remote Explorer WSL
Targets) and enter the container using the `Remote-Containers: Reopen in Container` command.

# Propel CI/CD

Build.GE's `Propel` self service CI/CD system is used to create a Jenkins pipeline to automatically build,
unit test and deploy (to Artifactory) the Go application. To learn how to setup this facility please see the
following page: [DevOps CTT - Propel CI/CD](https://stamp.gs.ec.ge.com/confluence/x/tQjOL). The file `Jenkinsfile`
defines the build to `Jenkins` in declartive form.

# Integration with Predix Edge (Development Build)

## Manual method (using Edge Agent API)

Discover the IP address of the Predix Edge OS instance to which you want to deploy the application.

Copy the application `.tar.gz` file to the Predix Edge instance; for example:
```bash
scp ./diffie-hellman-service-1.0.0-amd64.tar.gz root@$IPADDR:/mnt/data/.
```
where `IPADDR` is the IP address of the target.

Login to the target using ssh and deploy the application giving it an instance identifer of `diffie-hellman-service`:
```bash
cd /mnt/data
curl http://localhost/api/v1/applications \
    --unix-socket /var/run/edge-core/edge-core.sock \
    -X POST \
    -F "file=@diffie-hellman-service-1.0.0-amd64.tar.gz" \
    -H "app_name: diffie-hellman-service"
```

The application can subsequently be deleted as follows:
```bash
curl http://localhost/api/v1/applications/diffie-hellman-service \
    --unix-socket /var/run/edge-core/edge-core.sock \
    -X DELETE
```

## Manual method (using ssh and Edge Agent tools)

Discover the IP address of the Predix Edge OS instance to which you want to deploy the application.

Two shell scripts `scp-file.sh` and `ssh-deploy.sh` are provided to perform this task (tested only on Linux)

Copy the application `.tar.gz` file to the Predix Edge instance; for example:
```bash
scp ./diffie-hellman-service-1.0.0-amd64.tar.gz root@$IPADDR:/mnt/data/.
```
where `IPADDR` is the IP address of the target.

Login to the target using ssh and deploy the application giving it an instance identifer of `diffie-hellman-service`,
note we are able to do this by remounting the root file system as read write:
```bash
mount -o rw,remount /
mv /mnt/data/diffie-hellman-service.tar.gz /opt/application-system-containers/diffie-hellman-service.tar.gz
docker stack rm diffie-hellman-service
set -o allexport
. /opt/edge-agent/edge-agent-environment
set +o allexport
sleep 5
/opt/edge-agent/app-deploy diffie-hellman-service /opt/application-system-containers/diffie-hellman-service.tar.gz
```

The application can subsequently be deleted as follows:
```bash
/opt/edge-agent/app-delete --appInstanceId=diffie-hellman-service
```

## Predix Edge Technician Console (PETC) Method

Use PETC as described here: [PETC](https://docsstaging.predix.io/en-US/content/service/edge_software_and_services/predix_edge_device_configuration_and_enrollment/) to upload and manage the application.
