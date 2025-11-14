# simpleCryptoBackendSecret

## Prerequisite

- CRC deployed;
- At this time (2025-11-14) this barbican patch:
    - https://github.com/openstack-k8s-operators/barbican-operator/pull/305


### Files

To make this setup more self-contained, this is the content of the files I'm using:


not-osp-secret.yaml:

~~~bash
apiVersion: v1
kind: Secret
metadata:
  name: not-osp-secret
  namespace: openstack
type: Opaque
data:
  BarbicanSimpleCryptoKEK: MTIzNDU2Nzg=
~~~


### Steps

~~~bash
oc apply -f not-osp-secret.yaml
oc get secret not-osp-secret -o jsonpath='{.data.BarbicanSimpleCryptoKEK}' | base64 --decode
# Check the secret

EDITOR=vim oc edit
# from:
# spec:
#   barbican:
#       simpleCryptoBackendSecret: osp-secret
#
# to:
# spec:
#   barbican:
#       simpleCryptoBackendSecret: not-osp-secret

EDITOR=vim oc edit secrets not-osp-secret
# from:
# apiVersion: v1
# data:
#   BarbicanSimpleCryptoKEK: MTIzNDU2Nzg=
#
# to:
# apiVersion: v1
# data:
#   BarbicanSimpleCryptoKEK: MTIzNDU2Nzg5Cg=

oc get pods | grep barbican
# Check the pods were recreated

oc rsh -c barbican-api <barbican-api-pod>
cat /var/lib/config-data/default/00-default.conf | grep kek
# Check the kek was updated
~~~
