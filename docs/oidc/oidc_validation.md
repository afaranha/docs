# Validate OIDC - WIP


## Source

1. https://github.com/afaranha/docs/blob/main/docs/env/01_crc_deploy.md
1. https://github.com/afaranha/docs/blob/main/docs/env/02_federation.md
1. https://github.com/openstack-k8s-operators/data-plane-adoption/pull/1062/changes


## Steps

Follow the doc until this step:

~~~bash
oc extract secret/router-ca --keys=tls.crt -n openshift-ingress-operator
~~~

Then, start adding the PR steps:

~~~bash
oc create secret generic keycloakca --from-file=KeyCloakCA=tls.crt -n openstack
# secret/keycloakca created
touch keystone-httpd-override.yaml
~~~

Create keystone-httpd-override.yaml, with variables:
client_secret: COX8bmlKAWn56XCGMrKQJj7dgHNAOl6f
crypto_passphrase: openstack
client_secret: COX8bmlKAWn56XCGMrKQJj7dgHNAOl6f

~~~bash
apiVersion: v1
kind: Secret
metadata:
  name: keystone-httpd-override
  namespace: openstack
type: Opaque
stringData:
  federation.conf: |
    OIDCClaimPrefix "OIDC-"
    OIDCResponseType "code"
    OIDCScope "openid profile email"
    OIDCClaimDelimiter ","
    OIDCPassUserInfoAs "payload"
    OIDCPassClaimsAs "both"
    OIDCProviderMetadataURL "https://keycloak-openstack.apps-crc.testing/auth/realms/openstack/.well-known/openid-configuration"
    OIDCClientID "rhoso"
    OIDCClientSecret "COX8bmlKAWn56XCGMrKQJj7dgHNAOl6f"
    OIDCCryptoPassphrase "openstack"
    OIDCOAuthClientID "rhoso"
    OIDCOAuthClientSecret "COX8bmlKAWn56XCGMrKQJj7dgHNAOl6f"
    OIDCOAuthIntrospectionEndpoint "https://keycloak-openstack.apps-crc.testing/auth/realms/openstack/protocol/openid-connect/token/introspect"
    OIDCRedirectURI "https://keystone-public-openstack.apps-crc.testing/v3/auth/OS-FEDERATION/identity_providers/kcIDP/protocols/openid/websso/"
    LogLevel debug

    <LocationMatch "/v3/auth/OS-FEDERATION/identity_providers/kcIDP/protocols/openid/websso">
      AuthType "openid-connect"
      Require valid-user
    </LocationMatch>

    <Location "/v3/OS-FEDERATION/identity_providers/kcIDP/protocols/openid/auth">
      AuthType oauth20
      Require valid-user
    </Location>

    <LocationMatch "/v3/auth/OS-FEDERATION/websso/openid">
      AuthType "openid-connect"
      Require valid-user
    </LocationMatch>
~~~

~~~bash
oc apply -f keystone-httpd-override.yaml
# secret/keystone-httpd-override created

EDITOR=vim oc edit openstackcontrolplanes.core.openstack.org
# Under spec/tls add `caBundleSecretName: keycloakca`:
# spec:
#   [...]
#   tls:
#     caBundleSecretName: keycloakca # ADDED LINE
#     ingress:
#       ca:
#         duration: 87600h0m0s
#     [...]
#
# Under spec/keystone/template/httpdCustomization add `customConfigSecret: keystone-httpd-override`:
# spec:
#   [..]
#   keystone:
#     apiOverride:
#       route:
#     [...]
#     template:
#       adminProject: admin
#       [...]
#       fernetRotationDays: 1
#       httpdCustomization:
#         processNumber: 3
#         customConfigSecret: keystone-httpd-override # ADDED LINE
#       memcachedInstance: memcached
#
# Under spec/keystone/template add `customServiceConfig` with the following values:
# spec:
#   [..]
#   keystone:
#     apiOverride:
#       route:
#     [...]
#     template:
#       adminProject: admin
#       [...]
#       trustFlushSuspend: false
#       # ADDED LINES
#       customServiceConfig: |
#         [token]
#         expiration = 360000
#         [federation]
#         trusted_dashboard=https://horizon-openstack.apps-crc.testing/dashboard/auth/websso/
#         sso_callback_template=/etc/keystone/sso_callback_template.html
#         [openid]
#         remote_id_attribute=HTTP_OIDC_ISS
#         [auth]
#         methods = password,token,oauth1,mapped,application_credential,openid
#         [trusted_ip]
#         trusted_forwarded_for_header=True
#       # END OF ADDED LINES
~~~

~~~bash
alias openstack="oc exec -n openstack -t openstackclient -- openstack"
openstack domain create SSO
openstack identity provider create --remote-id https://keycloak-openstack.apps-crc.testing/auth/realms/openstack --domain SSO kcIDP

touch rules.json
~~~

rules.json
~~~bash
[
  {
    "local": [
        {
            "user": {
             "name": "{0}"
        },
        "group": {
            "name": "SSOgroup",
            "domain": {
                "name": "SSO"
            }
          }
        }
    ],
    "remote": [
      {
        "type": "OIDC-preferred_username"
      }
    ]
  }
]
~~~

~~~bash
oc cp rules.json openstack/openstackclient:/home/cloud-admin/rules.json -n openstack
# To check what was created:
#   oc exec -t openstackclient -n openstack -- ls

openstack mapping create --rules rules.json SSOmap
openstack group create --domain SSO SSOgroup
openstack project create --domain SSO SSOproject
openstack role add --group SSOgroup --group-domain SSO --project SSOproject --project-domain SSO member
openstack federation protocol create openid --mapping SSOmap --identity-provider kcIDP
~~~


## Testing

This test doesn't make sense on an env that wasn't adopted, but even so the results weren't positive.

~~~bash
openstack token issue

oc exec -t openstackclient -- env -u OS_CLOUD - \
    OS_AUTH_URL=https://keystone-public-openstack.apps-crc.testing/v3 \
    OS_AUTH_TYPE=v3oidcaccesstoken \
    OS_ACCESS_TOKEN=$(openstack token issue -f value -c id) \
    openstack project show admin
# Missing value identity-provider required for auth plugin v3oidcaccesstoken
# Missing value protocol required for auth plugin v3oidcaccesstoken
# command terminated with exit code 1
~~~

~~~bash
~~~

~~~bash
~~~

~~~bash
~~~

~~~bash
~~~