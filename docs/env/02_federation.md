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
