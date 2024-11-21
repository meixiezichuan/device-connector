# deviceConnector

This project implements the podProxy and deviceProxy in EdgeConnector, both of which leverage XDP technology for service request forwarding and device information forwarding.



## Build
```shell
make build
```

After build, you can get two binary in ./bin:
```shell
ls bin
```

## Run

Run podProxy in superior cluster.
Below is an example: replace the placeholders with your values for SUBIP and SUBMAC.
SUBIP and SUBMAC are the IP address and MAC address of the node where deviceProxy is installed in the subordinate cluster.

```shell
SUBIP="10.0.2.6" SUBMAC="00:0d:3a:41:ce:f0" podproxy
```

Run deviceProxy in the subordinate cluster. 
Below is an example: replace the placeholders with your values for UPIFACE, DOWNIFACE, PODPROXY_IP, and PODPROXY_MAC.

```shell
UPIFACE="eth1" DOWNIFACE="eth0" PODPROXY_IP="10.0.2.7" PODPROXY_MAC="60:45:bd:35:14:0b" deviceproxy
```
