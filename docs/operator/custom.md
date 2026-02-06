# WIP - Deploy Custom Operator


## Prerequisite

1. [Deploy CRC](../env/01_crc_deploy.md)


### ATTENTION

On February 06, 2026, to deploy the env to test application credential it's needed to use this image: `quay.io/rh-ee-vfisarov/openstack-operator-index:testing-appcred-support-latest`.
On the `make openstack` step, it needs to be run like: `OPENSTACK_IMG=quay.io/rh-ee-vfisarov/openstack-operator-index:testing-appcred-support-latest make openstack` and then proceed with the other steps as usual.


## For Heat Operator


First enable it

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


## Testing

~~~bash
oc get appcred -n openstack -o yaml
# apiVersion: v1
# items: []
# kind: List
# metadata:
#   resourceVersion: ""
~~~


Enable `applicationCredential` for Heat

~~~bash
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

~~~bash
EDITOR=vim oc edit heat heat
# To add:
# spec:
#   expirationDays: 2
#   gracePeriodDays: 1
#   passwordSelector: HeatPassword
#   userName: heat
#   secret: osp-secret
#   roles:
#     - admin
#     - service
#   unrestricted: false
#   [...]
~~~

~~~bash
~~~

~~~bash
~~~


~~~bash
~~~

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
~~~

~~~bash
~~~

## Testing



# OLD

## For Heat Operator


Drop the operator's CSV's deployment replicas to 0.

~~~bash
oc get pods -n openstack-operators | grep heat
# heat-operator-controller-manager-7487768f6d-zdb4j                 1/1     Running     0             74m
~~~

~~~bash
CSV_NAME=$(oc get csv -n openstack-operators -l operators.coreos.com/openstack-operator.openstack-operators -o name)
oc patch "${CSV_NAME}" -n openstack-operators --type=json -p="[{'op': 'replace', 'path': '/spec/install/spec/deployments/0/spec/replicas', 'value': 0}]"
oc get deployment -n openstack-operators heat-operator-controller-manager
oc scale --replicas=0 -n openstack-operators deploy/heat-operator-controller-manager
~~~


Clone the repository with the code to test.

~~~bash
cd
git clone https://github.com/openstack-k8s-operators/heat-operator.git
cd heat-operator
git fetch origin pull/610/head:pr610
git checkout pr610
~~~


Enable heat:

~~~bash
EDITOR=vim oc edit oscp openstack-galera-network-isolation
# Set spec/heat/enabled to true
# spec:
#   [...]
#   heat:
#    apiOverride:
#      route:
#        metadata:
#          annotations:
#            api.heat.openstack.org/timeout: 600s
#            haproxy.router.openshift.io/timeout: 600s
#    cnfAPIOverride:
#      route:    
#        metadata: 
#          annotations:
#            api.heat.openstack.org/timeout: 600s
#            haproxy.router.openshift.io/timeout: 600s
#    enabled: true
#    template:
#      apiTimeout: 600
#      databaseAccount: heat
#      databaseInstance: openstack
#   [...]
~~~


Run the heat operator.

~~~bash
METRICS_PORT=19090 HEALTH_PORT=19091 PPROF_PORT=19092 make run
~~~


### Troubleshooting

In case of:

~~~bash
2026-02-02T14:22:05Z    ERROR   Reconciler error        {"controller": "heat", "controllerGroup": "heat.openstack.org", "controllerKind": "Heat", "Heat": {"name":"heat","namespace":"openstack"}, "namespace": "openstack", "name": "heat", "reconcileID": "c40b44bf-dd3a-4b99-bdca-fc7bf2104fa2", "error": "Get \"https://keystone-internal.openstack.svc:5000/\": dial tcp: lookup keystone-internal.openstack.svc: no such host"}
~~~

~~~bash
oc get svc keystone-internal -n openstack
# NAME                TYPE           CLUSTER-IP     EXTERNAL-IP   PORT(S)          AGE
# keystone-internal   LoadBalancer   10.217.4.191   172.17.0.80   5000:31345/TCP   62m
sudo vi /etc/hosts
# Add:
# 127.0.0.1 keystone-internal.openstack.svc
oc port-forward -n openstack service/keystone-internal 5000:5000
~~~

~~~bash
oc get pods -n openstack | grep heat
# heat-api-7dd6c765d5-d8vtw                     1/1     Running     0          46s
# heat-cfnapi-56fd57c9d6-hjks8                  1/1     Running     0          46s
# heat-db-create-7zk5z                          0/1     Completed   0          7m35s
# heat-db-sync-hzq25                            0/1     Completed   0          7m30s
# heat-engine-69db484bf5-gstkf                  1/1     Running     0          48s
# heat-f994-account-create-update-54z7l         0/1     Completed   0          7m35s
~~~


### Testing

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

~~~bash
oc edit heat heat
# To add:
# spec:
#   expirationDays: 2
#   gracePeriodDays: 1
#   passwordSelector: HeatPassword
#   userName: heat
#   secret: osp-secret
#   roles:
#     - admin
#     - service
#   unrestricted: false
#   [...]
~~~


~~~bash
~~~


### OLD Testing

~~~bash
cd ~/install_yamls
make heat_prep

mkdir -p out/openstack/heat/cr/
cat <<EOF > out/openstack/heat/cr/heat_v1beta1_heat.yaml
apiVersion: heat.openstack.org/v1beta1
kind: Heat
metadata:
  name: heat
  namespace: openstack
spec:
  auth:
    applicationCredentialSecret: heat-app-cred-secret
  databaseInstance: openstack
  databaseUser: heat
  rabbitMqClusterName: rabbitmq
  secret: osp-secret
  heatAPI:
    containerImage: quay.io/openstack-k8s-operators/openstack-heat-api:latest
    replicas: 1
  heatCfnAPI:
    containerImage: quay.io/openstack-k8s-operators/openstack-heat-api:latest
    replicas: 1
  heatEngine:
    containerImage: quay.io/openstack-k8s-operators/openstack-heat-engine:latest
    replicas: 1
EOF
~~~


~~~bash
oc create secret generic heat-app-cred-secret -n openstack --from-literal=AppCredID=my-test-id --from-literal=AppCredSecret=my-test-secret
oc apply -f out/openstack/heat/cr/heat_v1beta1_heat.yaml
~~~

Inside the openstackclient pod, create the credential

~~~bash
oc rsh -n openstack openstackclient
openstack application credential create heat_test_auth --description "Test cred"
# +--------------+----------------------------------------------------------------------------------------+
# | Field        | Value                                                                                  |
# +--------------+----------------------------------------------------------------------------------------+
# | description  | Test cred                                                                              |
# | expires_at   | None                                                                                   |
# | id           | b6383f1ba1444b70a31e327f77dd0859                                                       |
# | name         | heat_test_auth                                                                         |
# | project_id   | 87aff196c3804d1995c8384f9895c70c                                                       |
# | roles        | member reader admin                                                                    |
# | secret       | gID487Qmvp7IpRB0FRv8ICS8_6K7q7PoynZ1ZXnF7vVaYqAlpGLMYH33v-PaH_4IbGsIaRwM0_K8oqN-sOu-pA |
# | system       | None                                                                                   |
# | unrestricted | False                                                                                  |
# | user_id      | 4dce5b7badd148f09a4ca0b713e8b030                                                       |
# +--------------+----------------------------------------------------------------------------------------+
~~~


~~~bash
oc create secret generic heat-app-cred-secret -n openstack --from-literal=AppCredID=b6383f1ba1444b70a31e327f77dd0859 --from-literal=AppCredSecret=gID487Qmvp7IpRB0FRv8ICS8_6K7q7PoynZ1ZXnF7vVaYqAlpGLMYH33v-PaH_4IbGsIaRwM0_K8oqN-sOu-pA
~~~


~~~bash
~~~


~~~bash
~~~

~~~bash
~~~

~~~bash
~~~

~~~bash
~~~


~~~bash
~~~


~~~bash
~~~

~~~bash
~~~
