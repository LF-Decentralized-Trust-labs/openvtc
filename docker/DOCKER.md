# OpenVTC in Docker

The `docker` folder contains `Dockerfile`s that can be used for generating a build environment and a slim, deployable OpenVTC container.

## Containerized deployment

To build the OpenVTC containerized deployment:

```bash
docker build -t openvtc -f ./docker/Dockerfile .
```

To run OpenVTC in the container:

```bash
docker run \
  --rm \
  -ti \
  -v "${PWD}/.vscode/data/root:/root" \
  --network host \
  openvtc
```

## Containerized build environment

To build the container for development:

```bash
docker build -t openvtc-builder -f ./docker/builder.Dockerfile .
```

To utilize cargo inside the build environment as your current user, while keeping the cargo cache and user home directory in a centralized folder under `.vscode/data`, use:

```bash
alias cargo='docker run --rm -ti -v "/etc/passwd:/etc/passwd:ro" -v "${PWD}/.vscode/data/home:${HOME}" -v "${PWD}:${PWD}" -w "${PWD}" -e CARGO_HOME=${HOME}/cargo --user $(id -u):$(id -g) -e HOME=${HOME} --network host openvtc-builder cargo'
```

From here out, all use of `cargo` will work just like using a standard Rust dev environment.

