# Vault Plugin: HashiCorp Cloud Platform (HCP) Backend

## Proof of Value
This Vault secrets plugin is not officially maintained or supported by HashiCorp. It exists as a proof of value for a Vault secrets engine
that can dynamically generate HCP service principal keys.

## TODO
- [ ] Locks
- [ ] Tests

## Important
- Organization level service principals are **very powerful** and should be used sparingly.
- Service Principals can only have **two** Service Principal Keys.
- Projects can only have **five** Service Principals.

## Overview
This is a standalone backend plugin for use with [Hashicorp
Vault](https://www.github.com/hashicorp/vault). This plugin generates revocable, time-limited service principals for HCP Projects.

Please note: We take Vault's security and our users' trust very seriously. If
you believe you have found a security issue in Vault, please responsibly
disclose by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links

- [Vault Website](https://developer.hashicorp.com/vault)
- [Vault Project GitHub](https://www.github.com/hashicorp/vault)

[//]: <> (Include any other quick links relevant to your plugin)

## Getting Started

This is a [Vault plugin](https://developer.hashicorp.com/vault/docs/plugins)
and is meant to work with Vault. This guide assumes you have already installed
Vault and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with
Vault](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-install).


## Usage

```shell
# mount
$ vault secrets enable hcp

# configure
$ vault write hcp/config \
   organization="..." \
   project="..." \
   client_id="..." \
   client_secret="..."

# read configuration
$ vault read hcp/config

# rotate initial credentials
$ vault write -f hcp/config/rotate

# configure a role
$ vault write hcp/roles/packer \
   role="contributor" \
   ttl="30m" \
   max_ttl="1h"

# list roles
$ vault list hcp/roles

# read role
$ vault read hcp/roles/packer

# generate credentials
$ vault read hcp/creds/packer

# delete role
$ vault delete hcp/roles/packer

# delete config
$ vault delete hcp/config
```

## Developing

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine.

If you're developing for the first time, run `make bootstrap` to install the
necessary tools. Bootstrap will also update repository name references if that
has not been performed ever before.

```sh
$ make bootstrap
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make dev
```

Put the plugin binary into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://developer.hashicorp.com/vault/docs/configuration#plugin_directory)
in the Vault config used to start the server.

```hcl
# config.hcl
plugin_directory = "path/to/plugin/directory"
...
```

Start a Vault server with this config file:

```sh
$ vault server -dev -config=path/to/config.hcl ...
...
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-catalog):

```sh
$ SHA256=$(openssl dgst -sha256 ./bin/vault-plugin-secrets-hcp | cut -d ' ' -f2)
$ vault plugin register \
        -sha256=$SHA256 \
        -command="vault-plugin-secrets-hcp" \
        secret hcp
...
Success! Registered plugin: hcp
```

Enable the secrets engine to use this plugin:

```sh
$ vault secrets enable hcp
...

Success! Enabled the hcp secrets engine at: hcp/
```

### Tests

To run the tests, invoke `make test`:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='-run=TestConfig'
```
