# CRC Deploy

## Prerequisite

- Server with:
    - VCPU: 64
    - RAM: 64GB
    - Size: 200GB
- Image: Fedora-Cloud-Base-41-latest


## Server Setup

This step will first install `tmux`, `vim`, `ansible-core`, `python3`, `git-core`, `make` and `gcc`.
And then it will configure tmux to use `Ctrl+a` as the prefix (personal preference),
`Shift+right` and `Shift+left` to change windows,
`Alt+right` and `Alt+left` to change panes.


### Files

To make this setup more self-contained, this is the content of the files I'm using:


setup.sh

~~~bash
#!/bin/bash

sudo dnf install tmux vim ansible-core python3 git-core make gcc -y
curl -o ~/.tmux.conf https://raw.githubusercontent.com/afaranha/AI-Test/refs/heads/main/tmux.conf
~~~


tmux.conf:

~~~bash
# Set prefix (Ctrl+a)
unbind C-b
set -g prefix C-a

bind -n M-Left  select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up    select-pane -U
bind -n M-Down  select-pane -D

bind -n S-Left  previous-window
bind -n S-Right next-window

bind c   new-window      -c "#{pane_current_path}"
bind %   split-window -h -c "#{pane_current_path}"
bind '"' split-window -v -c "#{pane_current_path}"

# List of plugins
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-resurrect'

set -g @continuum-restore 'on'

# Initialize TMUX plugin manager (keep this line at the very bottom of tmux.conf)
run '~/.tmux/plugins/tpm/tpm'
~~~


### Steps

~~~bash
curl -O https://raw.githubusercontent.com/afaranha/AI-Test/refs/heads/main/setup.sh
chmod +x setup.sh
./setup.sh

# tmux
# ctrl+a d
# exit
# ssh -t fedora@<IP> tmux a
~~~


## OpenShift / CRC Setup

~~~bash
vim ~/pull-secret.txt
# Create pull-secret.txt

git clone https://github.com/openstack-k8s-operators/install_yamls ~/install_yamls
cd ~/install_yamls/devsetup
make download_tools

PULL_SECRET=~/pull-secret.txt CPUS=12 MEMORY=25600 DISK=100 make crc

eval $(crc oc-env)
oc login -u kubeadmin -p 12345678 https://api.crc.testing:6443

make crc_attach_default_interface
# To check what was created: sudo virsh domiflist crc

cd ~/install_yamls
make crc_storage
# To check what was created:
#   oc get pv
#   oc get sc
~~~

## OpenStack Control Plane Deployment

~~~bash
make input
# To check what was created:
#   oc get secrets -n openstack
#   oc get configmaps -n openstack

make openstack
# If there's an issue on this step, try delete and run it again (double check the resource name):
#   oc delete nodenetworkconfigurationpolicy enp6s0-crc
# To check what was created:
#   oc get pods -n openstack-operators
#   oc get deployments -n openstack-operators
#   oc get services -n openstack-operators

make openstack_init
# To check what was created:
#   oc get crd | grep openstack
#   oc get pods -n openstack-operators

make openstack_deploy
# To check what was created:
#   oc get pods -n openstack
#   oc get deployments -n openstack
#   oc get statefulsets -n openstack
#   oc get services -n openstack
#   oc get routes -n openstack

oc get pods
oc get oscp
# Wait
~~~


## Dataplane Configuration (Optional)

~~~bash
DATAPLANE_TOTAL_NODES=1 make edpm_wait_deploy
oc -n openstack rsh openstackclient
openstack compute service list
exit
~~~

