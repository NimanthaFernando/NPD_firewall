## 1. Dependencies
## Insatll scapy
To install Scapy on a Linux system, you can use the following command:
```sh
sudo apt-get install python3-scapy
OR
sudo yum install python3-pip
```
if you want to install Scapy via pip (Python package manager), you can use:
```sh
pip install scapy
```
## Install Python GUI
```sh
2.yum install python3-tkinter
```
## Download pyroute2

```sh
pip3 install pyroute2 
```
if you faced the problem !

Note:-

when pyroute2 download(can not directly install because its broken permissions and conflicting behaviour with the system package manager then you need to create virtual enviroment)

WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager. 
It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv

## 2. Installations
Install virtualenv using pip: First, ensure pip is installed

    yum install python3-pip

then install virtualenv:

    pip3 install virtualenv

Create a virtual environment:

    virtualenv myenv(name)

Activate the virtual environment:

    source myenv/bin/activate

then install pyroute2:

    pip3 install pyroute2

Ensure that IP forwarding is enabled on VM 2 so that it can route packets between the two networks:

    sysctl -w net.ipv4.ip_forward=1
----------------------------------------------------------
    sudo ip route delete 172.168.3.0/24 dev ens160



