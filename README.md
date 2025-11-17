
<div align="center">
  <img src="Diemos-fw-2.png" alt="Diemos-fw logo" style="width: 100%; max-width: 1000px;">
</div>

## Description
Diemos-fw acts as an abstraction layer for iptables
Diemos-fw simplifies firewall rule management by providing a clean, readable syntax. It eliminates the tedious work of writing raw iptables/nftables commands, allowing administrators to focus on designing effective security policies rather than wrestling with complex implementation details.

## Feature
### 1.Stateful Connection Handling (Implicit)  
Automatically creates matching OUTPUT rules for allowed INPUT connections  

### 2.Rule Precedence Management  
New rules are inserted at the top of the chain (position #1)  

### 3.Advance Filtering  
Port-Specific Filtering  -> also ipv6  
Host-Based Filtering

### 4.Rule Existence Validation
Prevents duplicate rule creation by checking if a rule already exists in the database before adding it
Improves performance by preventing unnecessary iptables/ip6tables commands

### 5.Complete Rules Flush Functionality
Clears all firewall rules with the flush command



## Installing Diemos-fw
The package need to be compiled so make sure you have "GO"
```bash
git clone https://github.com/M0G3H/Diemos-fw.git
go build
install -m 755 Diemos-fw /usr/local/bin
```
and if you want Diemos-fw to be always up , do this
```bash
cp Diemos-fw.service /etc/systemd/system/
systemctl daemon-reload
systemctl start Diemos-fw.service
systemctl enable Diemos-fw.service
```

## Getting started
just type `Diemos-fw`  

some example:  
`Diemos-fw allow --host 192.168.134.130 --proto tcp --port 80`  
`Diemos-fw deny --host 54.239.28.85 --proto udp --port 4000`
