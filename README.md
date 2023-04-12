
AOS-Switch Ansible Collection
=========

This Ansible Network collection provides a set of platform dependent configuration
 management modules specifically designed for the AOS-Switch Ansible Collection
 network device.

Requirements
------------

* Python 2.7 or 3.5+
* Ansible 2.9.0 or later
  * Ansible 2.10+ requires `ansible.netcommon` collection to be installed  
* For AOS-Switch firmware version 16.08 and above is supported
* Enable REST on your AOS-Switch device with the following commands:
    ```
    switch(config)# web-management ssl
    switch(config)# rest-interface
    ```
* If you use RADIUS or TACACS for switch managment add also this command
    ```
    switch(config)# aaa authentication rest login radius local
    switch(config)# aaa authentication rest enable radius local
    ```
* Install all Ansible requirements, with the following command:
    ```
    ansible-galaxy install -r requirements.yml
    ```

Installation
------------

Through Galaxy:

```
ansible-galaxy collection install arubanetworks.aos_switch
```

Inventory Variables
--------------

The variables that should be defined in your inventory for your AOS-Switch host are:

* `ansible_host`: IP address of switch in `A.B.C.D` format. For IPv6 hosts use a string and enclose in square brackets E.G. `'[2001::1]'` 
* `ansible_user`: Username for switch in `plaintext` format  
* `ansible_password`: Password for switch in `plaintext` format  
* `ansible_connection`: Set to local to use REST API modules, and to network_cli to use SSH/CLI modules
    See below for info on using both REST API modules and SSH/CLI modules on a host
* `ansible_network_os`: Must always be set to `arubanetworks.aos_switch.arubaoss`  

### Sample Inventory:

#### YAML

```yaml
all:
  hosts:
    aosswitch_1:
      ansible_host: 10.0.0.1
      ansible_user: admin
      ansible_password: password
      ansible_connection: local  # REST API connection method
      ansible_network_os: arubanetworks.aos_switch.arubaoss  # Do not change
```

Setting Environment Variables
--------------
In order to use the AOS-Switch collection you need to modify your environment in order for Ansible to recognize the Network OS:  

Example of setting environment variable in the command :
 `$ ANSIBLE_NETWORK_GROUP_MODULES=arubaoss  ansible-playbook sample_playbook.yml -i inventory.yml`   

 You can also check which ansible.cfg is used by increasing the verbosity (add -v to command above) and accordingly set the value of NETWORK_GROUP_MODULES to "arubaoss" in the [defaults] section.
```
[defaults]
NETWORK_GROUP_MODULES=arubaoss
```

Example Playbook
----------------
If collection installed through [Galaxy](https://galaxy.ansible.com/arubanetworks/aos-switch)
add `arubanetworks.aos_switch` to your list of collections:

```yaml
    ---
    -  hosts: all
       collections:
         - arubanetworks.aos_switch
       tasks:
         - name: Create VLAN 300
           arubaoss_vlan:
             vlan_id: 300
             name: "vlan300"
             config: "create"
             command: config_vlan
```

SSH/CLI Modules
----------------
* To use the SSH/CLI modules `arubaoss_config` and `arubaoss_command`, SSH access must
 be enabled on your AOS-Switch device. It is enabled by default.
    * If necessary, re-enable SSH access on the device with the following command:
    ```
    switch(config)# ip ssh
    ```
* The control machine's `known_hosts` file must contain the target device's public key.
    * Alternatively, host key checking by the control machine may be disabled, although this is not recommended.
    * To disable host key checking modify the ansible.cfg file (default /etc/ansible/ansible.cfg) to include:
      `host_key_checking = false`
      
Using Both REST API and SSH/CLI Modules on a Host
----------------

To use both REST API and SSH/CLI modules on the same host, 
you must create separate plays such 
that each play uses either only REST API modules or only SSH/CLI modules.
A play cannot mix and match REST API and SSH/CLI module calls.
In each play, `ansible_connection` must possess the appropriate value 
according to the modules used. 
If the play uses REST API modules, the value should be `local`. 
If the play uses SSH/CLI modules, the value should be `network_cli`.
 
A recommended approach to successfully using both types of modules for a host
is as follows:
1. Set the host variables such that Ansible will connect to the host using REST API.
2. In the playbook, in each play wherein the SSH/CLI
modules are used, set the `ansible_connection` to `network_cli`. 

The inventory should look something like this:

```yaml
all:
  hosts:
    switch1:
      ansible_host: 10.0.0.1
      ansible_user: admin
      ansible_password: password
      ansible_connection: local  # REST API connection method
      ansible_network_os: arubanetworks.aos_switch.arubaoss  # Do not change
```

and the playbook like this (note how the second play, which uses the SSH/CLI module `arubaoss_command`,
sets the `ansible_connection` value accordingly):

```yaml
- hosts: all
  collections:
    - arubanetworks.aos_switch
  tasks:
    - name: Create VLAN 300
      arubaoss_vlan:
        vlan_id: 300
        name: "vlan300"
        config: "create"
        command: config_vlan

- hosts: all
  collections:
    - arubanetworks.aos_switch
  vars:
    ansible_connection: network_cli
  tasks:
    - name: Execute show run on the switch
      arubaoss_command:
        commands: ['show run']
```

Contribution
-------
At Aruba Networks we're dedicated to ensuring the quality of our products, if you find any
issues at all please open an issue on our [Github](https://github.com/aruba/aos-switch-ansible-collection) and we'll be sure to respond promptly!

For more contribution opportunities follow our guidelines outlined in our [CONTRIBUTING.md](https://github.com/aruba/aos-switch-ansible-collection/blob/master/CONTRIBUTING.md)

License
-------

Apache-2.0

Author Information
------------------
 - Tiffany Chiapuzio-Wong (@tchiapuziowong)
 - Sunil Veeramachaneni (@sunil.veeramachaneni)
 - Castro, Jorge Arturo (@jorge.castro93)

