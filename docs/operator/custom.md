# WIP - Deploy Custom Operator


## Prerequisite

1. [Deploy CRC](../env/01_crc_deploy.md)


### ATTENTION

On February 06, 2026, to deploy the env to test application credential it's needed to use this image: `quay.io/rh-ee-vfisarov/openstack-operator-index:testing-appcred-support-latest`.

On the `make openstack` step, it needs to be run like:

~~~bash
OPENSTACK_IMG=quay.io/rh-ee-vfisarov/openstack-operator-index:testing-appcred-support-latest make openstack
~~~

Proceed with the other steps as usual.


## For Heat Operator

First enable it:

~~~bash
EDITOR=vim oc edit oscp openstack-galera-network-isolation
# Set spec/heat/enabled to true
#  heat:
#    [...]
#    enabled: true
~~~

~~~bash
oc get pods -n openstack | grep heat
# heat-1cb2-account-create-update-qzp7s         0/1     Completed   0          3m24s
# heat-api-66f7c68fb4-szbl4                     1/1     Running     0          2m42s
# heat-cfnapi-6549d6cf46-s2vgl                  1/1     Running     0          2m42s
# heat-db-create-tkcgn                          0/1     Completed   0          3m25s
# heat-db-sync-6gz98                            0/1     Completed   0          3m19s
# heat-engine-654fbf86b-mtrdw                   1/1     Running     0          2m45s
~~~


Then enable Application Credential:

~~~bash
oc get appcred -n openstack -o yaml
# apiVersion: v1
# items: []
# kind: List
# metadata:
#   resourceVersion: ""
~~~

Enable `applicationCredential` for Heat:

~~~bash
EDITOR=vim oc edit oscp openstack-galera-network-isolation
# Set spec/applicationCredential/enabled to true
# spec:
#   applicationCredential:
#     enabled: true
#     expirationDays: 730
#     gracePeriodDays: 364
#     roles:
#     - admin
#     - service
#     unrestricted: false
#
# Set spec/heat/applicationCredential/enabled to true
#   heat:
#     [...]
#     applicationCredential:
#       enabled: true
~~~

Create a patch to create it:

~~~bash
cat <<EOF > ac_cr.yaml
apiVersion: keystone.openstack.org/v1beta1
kind: KeystoneApplicationCredential
metadata:
  name: ac-heat
  namespace: openstack
spec:
  expirationDays: 2
  gracePeriodDays: 1
  passwordSelector: HeatPassword
  userName: heat
  secret: osp-secret
  roles:
    - admin
    - service
  unrestricted: false
EOF
~~~

~~~bash
oc apply -f ac_cr.yaml
oc get appcred ac-heat -n openstack -o yaml
oc get secret ac-heat-secret -o yaml
~~~

Edit Heat again, this time to to update `applicationCredentialSecret` with the secret:

~~~bash
EDITOR=vim oc edit oscp openstack-galera-network-isolation
# Set spec/heat/template//auth/applicationCredentialSecret to ac-heat-secret
#   heat:
#     [...]
#     applicationCredential:
#       enabled: true
#   [...]
#     enabled: true
#     template:
#       apiTimeout: 600
#       auth:
#         applicationCredentialSecret: ac-heat-secret
#       [...]
~~~

Check if heat configuration was updated properly:

~~~bash
oc rsh -n openstack deploy/heat-api
view /etc/heat/heat.conf.d/00-default.conf 
# [...]
# [keystone_authtoken]
# www_authenticate_uri=https://keystone-internal.openstack.svc:5000

# auth_type = v3applicationcredential
# application_credential_id = f3f59db905cf4f5193b6394332ef5539
# application_credential_secret = s2maLKWfxamvSvrqUkGQoJFcfqJGURXpBGyYeGX6axMt_CpYFVFP1LoNmBDSBucuwq0Ja-nWBXg8mQcJy77Vww
# memcache_use_advanced_pool=True
# memcached_servers=memcached-0.memcached.openstack.svc:11212
# region_name=regionOne
# auth_url=https://keystone-internal.openstack.svc:5000
# interface=internal
~~~

## Testing


~~~bash
oc rsh -n openstack openstackclient
cat <<EOF > test-stack.yaml
heat_template_version: 2018-08-31
resources:
  test_resource:
    type: OS::Heat::TestResource
    properties:
      value: "AppCred Test Successful"
EOF
~~~

~~~bash
openstack stack create -t test-stack.yaml my-appcred-test
# +---------------------+--------------------------------------+
# | Field               | Value                                |
# +---------------------+--------------------------------------+
# | id                  | ac6ba8ec-d836-4cbd-8ffc-4af52a9e1a43 |
# | stack_name          | my-appcred-test                      |
# | description         | No description                       |
# | creation_time       | 2026-02-06T15:50:05Z                 |
# | updated_time        | None                                 |
# | stack_status        | CREATE_IN_PROGRESS                   |
# | stack_status_reason | Stack CREATE started                 |
# +---------------------+--------------------------------------+
~~~

~~~bash
openstack stack list
# +--------------------------------------+-----------------+----------------------------------+-----------------+----------------------+--------------+
# | ID                                   | Stack Name      | Project                          | Stack Status    | Creation Time        | Updated Time |
# +--------------------------------------+-----------------+----------------------------------+-----------------+----------------------+--------------+
# | ac6ba8ec-d836-4cbd-8ffc-4af52a9e1a43 | my-appcred-test | 9b79e35ed6644fda9ada57195277e5f5 | CREATE_COMPLETE | 2026-02-06T15:50:05Z | None         |
# +--------------------------------------+-----------------+----------------------------------+-----------------+----------------------+--------------+
~~~