# Federation Deploy


### Files


rhsso-operator-olm.yaml
~~~bash
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: rhsso-operator-group
spec:
  targetNamespaces:
  - openstack
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: rhsso-operator
spec:
  channel: stable
  installPlanApproval: Manual
  name: rhsso-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
~~~


credential-sso.yaml
~~~bash
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: credential-sso
  namespace: openstack
data:
  ADMIN_USERNAME: YWRtaW4= # echo -n "admin" | base64
  ADMIN_PASSWORD: bm9tb3Jlc2VjcmV0cw== # echo -n "nomoresecrets" | base64
~~~


sso.yaml
~~~bash
apiVersion: keycloak.org/v1alpha1
kind: Keycloak
metadata:
  name: sso
  labels:
    app: sso
spec:
  instances: 1
  externalAccess:
    enabled: True
~~~


rules_sso.json
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


rules_sso2.json
~~~bash
[
  {
    "local": [
        {
            "user": {
             "name": "{0}"
        },
        "group": {
            "name": "SSOgroup2",
            "domain": {
                "name": "SSO2"
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


keystone-httpd-override.yaml
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
    OIDCResponseType "id_token"
    OIDCScope "openid email profile"
    OIDCClaimDelimiter ";"
    OIDCPassUserInfoAs "claims"
    OIDCPassClaimsAs "both"
    OIDCCryptoPassphrase "openstack"
    OIDCMetadataDir "/var/lib/httpd/metadata"
    OIDCRedirectURI "https://keystone-public-openstack.apps-crc.testing/v3/redirect_uri"
    LogLevel debug

    <LocationMatch "/v3/auth/OS-FEDERATION/identity_providers/kcIDP/protocols/openid/websso">
      AuthType "openid-connect"
      Require valid-user
    </LocationMatch>

    <Location ~ "/v3/OS-FEDERATION/identity_providers/kcIDP/protocols/openid/auth">
      AuthType oauth20
      Require valid-user
    </Location>

    <LocationMatch "/v3/auth/OS-FEDERATION/identity_providers/kcIDP2/protocols/openid/websso">
      AuthType "openid-connect"
      Require valid-user
    </LocationMatch>

    <Location ~ "/v3/OS-FEDERATION/identity_providers/kcIDP2/protocols/openid/auth">
      AuthType oauth20
      Require valid-user
    </Location>

    <Location ~ "/redirect_uri">
      Require valid-user
      AuthType openid-connect
    </Location>

    <LocationMatch "/v3/auth/OS-FEDERATION/websso/openid">
      AuthType "openid-connect"
      Require valid-user
    </LocationMatch>
~~~


keycloak_realm.yaml
~~~bash
- name: Run federation SSO setup
  hosts: "{{ cifmw_target_host | default('localhost') }}"
  gather_facts: true
  tasks:
  - name: set my facts
    ansible.builtin.set_fact:
      cifmw_federation_keycloak_url: "https://keycloak-openstack.apps-crc.testing"
      cifmw_federation_keycloak_admin_username: admin
      cifmw_federation_keycloak_admin_password: nomoresecrets
      cifmw_federation_keycloak_realm: openstack
      cifmw_federation_keycloak_realm2: openstack2
      cifmw_federation_keycloak_client_id: rhoso
      cifmw_federation_keycloak_client2_id: rhoso2
      cifmw_federation_keystone_url: "https://keystone-public-openstack.apps-crc.testing"
      cifmw_federation_keycloak_client_secret: COX8bmlKAWn56XCGMrKQJj7dgHNAOl6f
      cifmw_federation_keycloak_client2_secret: COX8bmlKAWn56XCGMrKQJj7dgHNAOl6f
      cifmw_federation_keycloak_idp_name: kcIDP
      cifmw_federation_keycloak_idp2_name: kcIDP2
      cifmw_federation_horizon_url: "https://horizon-openstack.apps-crc.testing"
      cifmw_federation_keycloak_url_validate_certs: false
      cifmw_federation_keycloak_testgroup1_name: kctestgroup1
      cifmw_federation_keycloak_testgroup2_name: kctestgroup2
      cifmw_federation_keycloak_testgroup3_name: kctestgroup3
      cifmw_federation_keycloak_testgroup4_name: kctestgroup4
      cifmw_federation_keycloak_testuser1_username: kctestuser1
      cifmw_federation_keycloak_testuser1_password: nomoresecrets1
      cifmw_federation_keycloak_testuser2_username: kctestuser2
      cifmw_federation_keycloak_testuser2_password: nomoresecrets2
      cifmw_federation_keycloak_testuser3_username: kctestuser3
      cifmw_federation_keycloak_testuser3_password: nomoresecrets3
      cifmw_federation_keycloak_testuser4_username: kctestuser4
      cifmw_federation_keycloak_testuser4_password: nomoresecrets4

  - name: Create a Keycloak realm
    community.general.keycloak_realm:
      auth_client_id: admin-cli
      validate_certs: false
      auth_keycloak_url: "{{ cifmw_federation_keycloak_url }}/auth"
      auth_realm: master
      auth_username: "{{ cifmw_federation_keycloak_admin_username }}"
      auth_password: "{{ cifmw_federation_keycloak_admin_password }}"
      id: "{{ cifmw_federation_keycloak_realm }}"
      realm: "{{ cifmw_federation_keycloak_realm }}"
      enabled: true
      state: present

  - name: Create a Keycloak realm2
    community.general.keycloak_realm:
      auth_client_id: admin-cli
      validate_certs: false
      auth_keycloak_url: "{{ cifmw_federation_keycloak_url }}/auth"
      auth_realm: master
      auth_username: "{{ cifmw_federation_keycloak_admin_username }}"
      auth_password: "{{ cifmw_federation_keycloak_admin_password }}"
      id: "{{ cifmw_federation_keycloak_realm2 }}"
      realm: "{{ cifmw_federation_keycloak_realm2 }}"
      enabled: true
      state: present

  - name: Create Keycloak client
    community.general.keycloak_client:
      auth_client_id: admin-cli
      validate_certs: false
      auth_keycloak_url: "{{ cifmw_federation_keycloak_url }}/auth"
      auth_realm: master
      auth_username: "{{ cifmw_federation_keycloak_admin_username }}"
      auth_password: "{{ cifmw_federation_keycloak_admin_password }}"
      state: present
      realm: "{{ item.name }}"
      client_id: "{{ item.client_id }}"
      name: 'RHOSO Client for {{ item.name }}'
      description: 'RHOSO client for keystone federation in {{ item.name }} realm'
      root_url: "{{ cifmw_federation_keystone_url }}"
      admin_url: "{{ cifmw_federation_keystone_url }}"
      base_url: '/dashboard/project'
      enabled: true
      client_authenticator_type: client-secret
      secret: "{{ item.client_secret }}"
      redirect_uris:
        - "{{ cifmw_federation_keystone_url }}/v3/auth/OS-FEDERATION/identity_providers/{{ item.idp_name }}/protocols/openid/websso/"
        - "{{ cifmw_federation_keystone_url }}/v3/auth/OS-FEDERATION/websso/openid"
        - "{{ cifmw_federation_keystone_url }}/v3/redirect_uri"
        - "{{ cifmw_federation_horizon_url }}/dashboard/auth/websso/"
      web_origins:
        - "{{ cifmw_federation_keystone_url }}"
        - "{{ cifmw_federation_horizon_url }}"
      bearer_only: false
      public_client: false
      implicit_flow_enabled: true
      protocol: openid-connect
    loop:
      - { name: "{{ cifmw_federation_keycloak_realm }}", client_id: "{{ cifmw_federation_keycloak_client_id }}", client_secret: "{{ cifmw_federation_keycloak_client_secret }}", idp_name: "{{ cifmw_federation_keycloak_idp_name }}" }
      - { name: "{{ cifmw_federation_keycloak_realm2 }}", client_id: "{{ cifmw_federation_keycloak_client2_id }}", client_secret: "{{ cifmw_federation_keycloak_client2_secret }}", idp_name: "{{ cifmw_federation_keycloak_idp2_name }}" }

  - name: Create a Keycloak groups
    community.general.keycloak_group:
      auth_client_id: admin-cli
      validate_certs: "{{ cifmw_federation_keycloak_url_validate_certs }}"
      auth_keycloak_url: "{{ cifmw_federation_keycloak_url }}/auth"
      auth_realm: master
      auth_username: "{{ cifmw_federation_keycloak_admin_username }}"
      auth_password: "{{ cifmw_federation_keycloak_admin_password }}"
      state: present
      name: "{{ item.name }}"
      realm: "{{ item.realm }}"
    loop:
      - { name: "{{ cifmw_federation_keycloak_testgroup1_name }}", realm: "{{ cifmw_federation_keycloak_realm }}" }
      - { name: "{{ cifmw_federation_keycloak_testgroup2_name }}", realm: "{{ cifmw_federation_keycloak_realm }}" }
      - { name: "{{ cifmw_federation_keycloak_testgroup3_name }}", realm: "{{ cifmw_federation_keycloak_realm2 }}" }
      - { name: "{{ cifmw_federation_keycloak_testgroup4_name }}", realm: "{{ cifmw_federation_keycloak_realm2 }}" }

  - name: Create keycloak users
    community.general.keycloak_user:
      auth_client_id: admin-cli
      validate_certs: "{{ cifmw_federation_keycloak_url_validate_certs }}"
      auth_keycloak_url: "{{ cifmw_federation_keycloak_url }}/auth"
      auth_realm: master
      auth_username: "{{ cifmw_federation_keycloak_admin_username }}"
      auth_password: "{{ cifmw_federation_keycloak_admin_password }}"
      state: present
      realm: "{{ item.realm }}"
      username: "{{ item.username }}"
      firstName: "{{ item.username | title }}"
      lastName: "User"
      email: "{{ item.username }}@{{ item.realm }}.openstack.lab"
      enabled: true
      emailVerified: false
      credentials:
        - type: password
          value: "{{ item.password }}"
          temporary: false
      groups:
        - name: "{{ item.group }}"
          state: present
    loop:
      - { username: "{{ cifmw_federation_keycloak_testuser1_username }}", password: "{{ cifmw_federation_keycloak_testuser1_password }}", group: "{{ cifmw_federation_keycloak_testgroup1_name }}", realm: "{{ cifmw_federation_keycloak_realm }}" }
      - { username: "{{ cifmw_federation_keycloak_testuser2_username }}", password: "{{ cifmw_federation_keycloak_testuser2_password }}", group: "{{ cifmw_federation_keycloak_testgroup2_name }}", realm: "{{ cifmw_federation_keycloak_realm }}" }
      - { username: "{{ cifmw_federation_keycloak_testuser3_username }}", password: "{{ cifmw_federation_keycloak_testuser3_password }}", group: "{{ cifmw_federation_keycloak_testgroup3_name }}", realm: "{{ cifmw_federation_keycloak_realm2 }}" }
      - { username: "{{ cifmw_federation_keycloak_testuser4_username }}", password: "{{ cifmw_federation_keycloak_testuser4_password }}", group: "{{ cifmw_federation_keycloak_testgroup4_name }}", realm: "{{ cifmw_federation_keycloak_realm2 }}" }
~~~


multi_realm_secret.yaml
~~~yaml
- name: Debug multi realm
  hosts: "{{ cifmw_target_host | default('localhost') }}"
  gather_facts: true
  tasks:
    - name: Set facts
      ansible.builtin.set_fact:
	cifmw_federation_keycloak_url_validate_certs: false
        cifmw_federation_keystone_OIDC_ProviderMetadataURL: "https://keycloak-openstack.apps-crc.testing/auth/realms/openstack/.well-known/openid-configuration"
        cifmw_federation_keystone_OIDC_ProviderMetadataURL2: "https://keycloak-openstack.apps-crc.testing/auth/realms/openstack2/.well-known/openid-configuration"
        cifmw_federation_keystone_idp1_conf_filename: "keycloak-openstack.apps-crc.testing%2Fauth%2Frealms%2Fopenstack.conf"
        cifmw_federation_keystone_idp1_client_filename: "keycloak-openstack.apps-crc.testing%2Fauth%2Frealms%2Fopenstack.client"
        cifmw_federation_keystone_idp2_conf_filename: "keycloak-openstack.apps-crc.testing%2Fauth%2Frealms%2Fopenstack2.conf"
        cifmw_federation_keystone_idp2_client_filename: "keycloak-openstack.apps-crc.testing%2Fauth%2Frealms%2Fopenstack2.client"
        cifmw_federation_keystone_OIDC_ClientID: "rhoso"
        cifmw_federation_keystone_OIDC_ClientSecret: "COX8bmlKAWn56XCGMrKQJj7dgHNAOl6f"
        cifmw_federation_keystone_OIDC_ClientID2: "rhoso2"
        cifmw_federation_keystone_OIDC_ClientSecret2: "COX8bmlKAWn56XCGMrKQJj7dgHNAOl6f"
        cifmw_federation_keystone_idp1_provider_filename: "keycloak-openstack.apps-crc.testing%2Fauth%2Frealms%2Fopenstack.provider"
        cifmw_federation_keystone_idp2_provider_filename: "keycloak-openstack.apps-crc.testing%2Fauth%2Frealms%2Fopenstack2.provider"

    - name: Download OpenID configuration
      ansible.builtin.uri:
        url: "{{ item }}"
        method: GET
        return_content: true
        validate_certs: "{{ cifmw_federation_keycloak_url_validate_certs }}"
      loop:
        - "{{ cifmw_federation_keystone_OIDC_ProviderMetadataURL }}"
        - "{{ cifmw_federation_keystone_OIDC_ProviderMetadataURL2 }}"
      register: openid_configs

    - name: Debug openid_configs
      debug:
        var: openid_configs

    - name: Set federation_config_items
      ansible.builtin.set_fact:
        federation_config_items:
          - filename: "{{ cifmw_federation_keystone_idp1_conf_filename }}"
            contents: |
              {
                "scope" : "openid email profile"
              }
          - filename: "{{ cifmw_federation_keystone_idp1_client_filename }}"
            contents: "{{ {'client_id': cifmw_federation_keystone_OIDC_ClientID, 'client_secret': cifmw_federation_keystone_OIDC_ClientSecret } | to_json }}"
          - filename: "{{ cifmw_federation_keystone_idp1_provider_filename }}"
            contents: |
              {{ openid_configs.results[0].content }}
          - filename: "{{ cifmw_federation_keystone_idp2_conf_filename }}"
            contents: |
              {
                "scope" : "openid email profile"
              }
          - filename: "{{ cifmw_federation_keystone_idp2_client_filename }}"
            contents: "{{ {'client_id': cifmw_federation_keystone_OIDC_ClientID2, 'client_secret': cifmw_federation_keystone_OIDC_ClientSecret2 } | to_json }}"
          - filename: "{{ cifmw_federation_keystone_idp2_provider_filename }}"
            contents: |
              {{ openid_configs.results[1].content }}

    - name: Generate the final federation_config.json string (as a dictionary)
      ansible.builtin.set_fact:
        _raw_federation_config_json_value: |
          {
          {% for item in federation_config_items %}
            "{{ item.filename }}": {{ item.contents }}{% if not loop.last %},{% endif %}
          {% endfor %}
          }

    - name: Add secret to federation_config_secret.yaml
      copy:
        dest: federation_config_secret.yaml
        content: |
          apiVersion: v1
          kind: Secret
          metadata:
            name: keystone-federation-config-v7
            namespace: openstack
          type: Opaque
          stringData:
            federation-config.json: |
              {{ _raw_federation_config_json_value | to_json }}
~~~


### Steps


#### Keycloak Install

~~~bash
oc apply -f rhsso-operator-olm.yaml
oc get installplan -n openstack
oc patch installplan <NAME> -n openstack --type=merge --patch '{"spec":{"approved":true}}'
# To check what was created:
#   oc get installplan -n openstack
#   oc get csv -n openstack
#   oc get deployments -n openstack
#   oc get pods | grep rhsso

oc apply -f credential-sso.yaml
# To check what was created:
#   oc get secret credential-sso -n openstack
#   oc get secret credential-sso -n openstack -o jsonpath='{.data.ADMIN_USERNAME}' | base64 --decode; echo
#   oc get secret credential-sso -n openstack -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 --decode; echo

oc apply -n openstack -f sso.yaml
# To check what was created:
#   oc get keycloak sso -n openstack
#   oc get pods -n openstack | grep keyc

sudo tee -a /etc/hosts > /dev/null << 'EOF'
# BEGIN CRC HOSTS
192.168.130.11 keycloak-openstack.apps-crc.testing
# END CRC HOSTS
EOF

oc extract secret/router-ca --keys=tls.crt -n openshift-ingress-operator
~~~


#### Keycloack Configure

~~~bash
ansible-galaxy collection install community.general

ansible-playbook keycloak_realm.yaml

ansible-playbook multi_realm_secret.yaml

oc apply -f federation_config_secret.yaml
~~~


#### OpenStack Configure

~~~bash
alias openstack="oc exec -n openstack -t openstackclient -- openstack"
openstack domain create SSO
openstack identity provider create --remote-id https://keycloak-openstack.apps-crc.testing/auth/realms/openstack --domain SSO kcIDP

oc cp rules_sso.json openstack/openstackclient:/home/cloud-admin/rules_sso.json -n openstack
# To check what was created:
#   oc exec -t openstackclient -n openstack -- ls

openstack mapping create --rules rules_sso.json SSOmap
openstack group create --domain SSO SSOgroup
openstack project create --domain SSO SSOproject
openstack role add --group SSOgroup --group-domain SSO --project SSOproject --project-domain SSO member
openstack federation protocol create openid --mapping SSOmap --identity-provider kcIDP


openstack domain create SSO2
openstack identity provider create --remote-id https://keycloak-openstack.apps-crc.testing/auth/realms/openstack2 --domain SSO2 kcIDP2

oc cp rules_sso2.json openstack/openstackclient:/home/cloud-admin/rules_sso2.json -n openstack
# To check what was created:
#   oc exec -t openstackclient -n openstack -- ls

openstack mapping create --rules rules_sso2.json SSOmap2
openstack group create --domain SSO2 SSOgroup2
openstack project create --domain SSO2 SSOproject2
openstack role add --group SSOgroup2 --group-domain SSO2 --project SSOproject2 --project-domain SSO2 member
openstack federation protocol create openid --mapping SSOmap2 --identity-provider kcIDP2


oc apply -f keystone-httpd-override.yaml
# To check what was created:
#   oc get secret keystone-httpd-override -n openstack
#   oc get secret keystone-httpd-override -n openstack -o jsonpath='{.data.federation\.conf}' | base64 --decode


oc apply -f - <<EOF
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: keycloakca
  namespace: "openstack"
data:
  KeyCloakCA: $(cat "tls.crt" | base64 -w 0)
EOF
# To check what was created:
#  oc get secret keycloakca -n openstack -o jsonpath='{.data.KeyCloakCA}' | base64 --decode

export EDITOR=vim
oc edit openstackcontrolplanes.core.openstack.org
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
# Under spec/keystone/template add `customServiceConfig` and `federatedRealmConfig` with the following values:
# spec:
#   [..]
#   keystone:
#     apiOverride:
#       route:
#     [...]
#     template:
#       adminProject: admin
#       [...]
#       federatedRealmConfig: "federation-realm-data"
#       [...]
#       trustFlushSuspend: false
#       # ADDED LINES
#       customServiceConfig: |
#         [DEFAULT]
#         insecure_debug=true
#         debug=true
#         [federation]
#         trusted_dashboard=https://horizon-openstack.apps-crc.testing/dashboard/auth/websso/
#         [openid]
#         remote_id_attribute=HTTP_OIDC_ISS
#         [auth]
#         methods = password,token,oauth1,mapped,application_credential,openid
#       # END OF ADDED LINES
~~~


### Enable Horizon


~~~bash
oc edit openstackcontrolplanes.core.openstack.org
# Under spec/horizon:
# 
#   horizon:
#     apiOverride:
#       route: {}
#     enabled: true # CHANGED
#     template:
#       customServiceConfig: |
#         OPENSTACK_KEYSTONE_URL = "https://keystone-public-openstack.apps-crc.testing/v3"
#         WEBSSO_ENABLED = True
#         WEBSSO_CHOICES = (
#           ("credentials", _("Keystone Credentials")),
#           ("OIDC1", _("OpenID Connect IdP1")),("OIDC2", _("OpenID Connect IdP2")),
#         )
#         WEBSSO_IDP_MAPPING = {
#           "OIDC1": ("kcIDP", "openid"),"OIDC2": ("kcIDP2", "openid"),
#         }

# To check what was created:
#   oc get pods | grep horizon
~~~


#### Testing It


Update your local /etc/hosts, and add the following:

~~~bash
127.0.0.1 horizon-openstack.apps-crc.testing
127.0.0.1 keystone-public-openstack.apps-crc.testing
127.0.0.1 keystone-internal-openstack.apps-crc.testing
127.0.0.1 keycloak-openstack.apps-crc.testing
~~~


Create a tunnel:


~~~bash
sudo ssh -L 443:keystone-public-openstack.apps-crc.testing:443 -N -i .ssh/<PRIVATE_KEY> fedora@<CRC IP>
~~~
