# Vault Secrets Plugin - Grafana Cloud

[Vault][vault] secrets plugins to simplying creation, management, and
revocation of [Grafana Cloud](https://grafana.com/docs/grafana-cloud/developer-resources/api-reference/cloud-api) API tokens.

## Usage

### Setup Endpoint

1. Download and enable plugin locally (TODO)

2. Configure the plugin

   ```
   vault write grafana-cloud/config/token token=$GRAFANA_CLOUD_TOKEN 
   ```

3. Add one or more policies

### Configure Policies
[docs](https://grafana.com/docs/grafana-cloud/developer-resources/api-reference/cloud-api/#create-an-access-policy)

```
# NOTE: this policy will not work and is just an example
vault write /grafana-cloud/access_policies/<role-name> policy=-<<EOF
{
  "displayName": "Stack Readers",
  "scopes": ["metrics:read", "logs:read", "traces:read", "alerts:read"],
  "realms": [
    {
      "type": "org",
      "identifier": "<org id>"
      ]
    }
  ]
}
EOF
```

you can then read from the role using

```
vault read /grafana-cloud/creds/<role-name>
```

### Generate a new Token

To generate a new token:

[Create a new grafana-cloud policy](#configure-policies) and perform a 'read' operation on the `creds/<role-name>` endpoint.

```bash
# To read data using the api
$ vault read grafana-cloud/role/single-use
Key                Value
---                -----
lease_id           grafana-cloud/creds/test/yfF2qCtSvKSakATS89va1Var
lease_duration     768h
lease_renewable    false
capabilities       map[devices:map[create:map[]]]
expires            2022-03-27T03:13:45Z
id                 koD1dv6CNTRL
token              <token>
```

## Development

The provided [Earthfile] ([think makefile, but using
docker](https://earthly.dev)) is used to build, test, and publish the plugin.
See the build targets for more information. Common targets include

```bash
# build a local version of the plugin
$ earthly +build

# start vault and enable the plugin locally
# update the GRAFANA_CLOUD_* variables in ./scripts/dev.sh
earthly +dev
```

[vault]: https://www.vaultproject.io/
[earthfile]: ./Earthfile
