# CNI Plugins

A collection of [Container Network Interface (CNI)](https://www.cni.dev/docs/spec/)
plugins for the container ecosystem.

Each plugin addresses a specific networking need and integrates through the
standard CNI interface, rather than a runtime-specific API. Plugins may provide
standalone networking or complement an existing network through chaining.
Supported platforms, configuration, and deployment modes are documented per plugin.

## Available plugins

### APIPA (Windows)

Adds an IPv4 link-local interface to Windows containers.
Runs standalone or chained, preserving primary networking and accepting caller-provided endpoint policies.
The plugin does not provide built-in peer isolation.

[Read the APIPA guide](cmd/apipa/README.md) for requirements, configuration,
address management, policies, and deployment instructions.

Example configurations:

- [Standalone networking](examples/standalone.conf)
- [Chaining with a primary network](examples/chained.conflist)

## Getting started

1. Check the plugin's README for supported platforms, CNI versions, and host requirements.
2. Follow its build and installation instructions for your CNI-enabled runtime.
3. Use the example configurations as templates, adapting them to your environment.

## Repository layout

- [cmd](cmd/): Plugin implementations, tests, and plugin-specific documentation.
- [examples](examples/): Example CNI configurations for standalone and chained use.

## License

Licensed under the [MIT License](LICENSE).
