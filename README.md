# PIM-SSM
We have implemented PIM-SSM multicast routing protocol (RFC7761, specifically following Section 4.8)
This repository stores the implementation of this protocol. The implementation is written in Python and is destined to Linux systems.

Additionally, IGMPv3 is implemented alongside with PIM-SSM to detect interest of hosts.


# Requirements

 - Linux machine
 - Unicast routing protocol*
 - Python3 (we have written all code to be compatible with at least Python v3.3)
 - pip (to install all dependencies)

*PIM-SSM uses the Linux unicast routing table for RPF checks and also to detect loops. 
For this reason the Linux routing table must have consistent information. However some routing packages like most recent versions of Quagga set the metric of routes with a dummy value causing PIM-SSM to false suspect a loop and to not create multicast trees as expected.

# Installation

  Download the pim_ssm

# Run PIM-SSM

You may need sudo permissions, in order to run this protocol. This is required because we use raw sockets to exchange control messages. For this reason, some sockets to work properly need to have super user permissions.

To interact with the protocol you need to execute the `python3 Run.py` command. You may need to specify a command and corresponding arguments:

   `python3 Run.py -COMMAND ARGUMENTS`
   
Only IPv4 multicast is supported.


#### Start protocol process

In order to start the protocol you first need to explicitly start it. This will start a daemon process, which will be running in the background.

   ```
   sudo python3 Run.py -start
   ```

#### Add interface

After starting the protocol process you can enable the protocol in specific interfaces. You need to specify which interfaces will have IGMPv3 enabled and which interfaces will have PIM-SSM enabled.
* To have a given interface being monitored by PIM-SSM (to exchange control packets with it), you need to run the following command:

  ```
  sudo python3 Run.py -ai INTERFACE_NAME
  ```

* To have a given interface being monitored by IGMPv3 (to monitor the IPv4 multicast interest of directly connected hosts), you need to run the following command:

  ```
  sudo python3 Run.py -aiigmp INTERFACE_NAME
  ```

#### Remove interface

To remove a previously added interface, you need to run the following commands:

* To remove a previously added PIM-SSM interface:

  ```
  sudo python3 Run.py -ri INTERFACE_NAME
  ```

* To remove a previously added IGMP interface:

  ```
  sudo python3 Run.py -riigmp INTERFACE_NAME
  ```

#### Stop protocol process

If you want to stop the protocol process, and stop the daemon process, you need to explicitly run this command:

   ```
   sudo python3 Run.py -stop
   ```

#### Change priority for DR

If you want to change the DR priority transmitted in Hello messages:

   ```
   sudo python3 Run.py -dr VALUE
   ```

## Commands for monitoring the protocol process
We have built some list commands that can be used to check the "internals" of the protocol.

 - #### List interfaces:

	 Show all router interfaces and which ones have PIM-SSM and IGMPv3 enabled. For IGMPv3 enabled interfaces outputs the Querier state. For HPIM enabled interfaces outputs security settings.

   ```
   sudo python3 Run.py -li
   ```

 - #### List neighbors:

	 Verify neighbors that have established a neighborhood relationship.

   ```
   sudo python3 Run.py -ln
   ```

 - #### List sequence numbers:

    Verify all stored sequence numbers.

   ```
   sudo python3 Run.py -lsn
   ```

 - #### List neighbor state:

    Verify all state regarding each neighbor, whether they are UPSTREAM or NOT UPSTREAM and in the latter whether they are INTERESTED or NOT INTERESTED in receiving data packets.

   ```
   sudo python3 Run.py -lns
   ```

 - #### List state machines:

    List all state machines and corresponding state of all trees that are being monitored. Also list IGMPv3 state for each group being monitored.

   ```
   sudo python3 Run.py -ls
   ```

 - #### Multicast Routing Table:

   List Linux Multicast Routing Table (equivalent to `ip mroute show`)

   ```
   sudo python3 Run.py -mr
   ```

Files tree/globals.py and igmpv3/igmp_globals.py store all timer values and some configurations regarding PIM-SSM and IGMPv3. If you want to tune the protocol, you can change the values of these files. These configurations are used by all interfaces, meaning that there is no tuning per interface.

## Help command
In order to determine which commands and corresponding arguments are available you can call the help command:

  ```
  python3 Run.py -h
  ```
