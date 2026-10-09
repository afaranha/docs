
~~~bash
export PATH="$HOME/Library/Python/3.14/bin:$HOME/.local/bin:$PATH"
export API_URL=https://paas-metadata-service-api.apps.mpp-w2-phub.e8ue.p1.openshiftapps.com

mpp c login -t prod-stable-spoke1-dc-rdu3

oc project rhos-ops-platformservices-security--afariasa

oc get vm

virtctl ssh centos@vm/<VM_NAME> --identity-file=~/.ssh/id_ed25519
~~~
