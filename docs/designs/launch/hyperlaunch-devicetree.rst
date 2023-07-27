-------------------------------------
Xen Hyperlaunch Device Tree Bindings
-------------------------------------

The Xen Hyperlaunch device tree is informed by the dom0less device tree
structure with extensions to meet the requirements for the Hyperlaunch
capability. A major depature from the dom0less device tree is the introduction
of the ``hypervisor`` node that is under the ``/chosen`` node. The move to a
dedicated node was driven by:

1. Reduces the need to walk over nodes that are not of interest, e.g. only
   nodes of interest should be in ``/chosen/hypervisor``

2. Allows for the domain construction information to easily be sanitized by
   simple removing the ``/chosen/hypervisor`` node.

The Hypervisor node
-------------------

The ``hypervisor`` node is a top level container for all information relating
to how the hyperlaunch is to proceed. This includes definitions of the domains
that will be built by hypervisor on start up. The node will be named
``hypervisor``  with a ``compatible`` property to identify which hypervisors
the configuration is intended. The hypervisor node will consist of one or more
config nodes and one or more domain nodes.

Properties
""""""""""

compatible
  Identifies which hypervisors the configuration is compatible. Required.

  Format: "hypervisor,<hypervisor name>", e.g "hypervisor,xen"

Child Nodes
"""""""""""

* config
* domain

Config Node
-----------

A ``config`` node is for passing configuration data and identifying any boot
modules that is of interest to the hypervisor.  For example this would be where
Xen would be informed of microcode or XSM policy locations. Each ``config``
node will require a unique device-tree compliant name as there may be one or
more ``config`` nodes present in a single dtb file. To identify which
hypervisor the configuration is intended, the required ``compatible`` property
must be present.

While the config node is not meant to replace the hypervisor commandline, there
may be cases where it is better suited for passing configuration details at
boot time.  This additional information may be carried in properties assigned
to a ``config`` node. If there are any boot modules that are intended for the
hypervisor, then a ``module`` child node should be provided to identify the
boot module.

Properties
""""""""""

compatible
  Identifies the hypervisor the confiugration is intended. Required.

  Format: "<hypervisor name>,config", e.g "xen,config"

bootargs
  This is used to provide the boot params for Xen.

  Format: String, e.g. "flask=silo"

Child Nodes
"""""""""""

* module

Domain Node
-----------

A ``domain`` node is for describing the construction of a domain. Since there
may be one or more domain nodes, each one requires a unique, DTB compliant name
and a ``compatible`` property to identify as a domain node.

A ``domain`` node  may provide a ``domid`` property which will be used as the
requested domain id for the domain with a value of “0” signifying to use the
next available domain id, which is the default behavior if omitted. It should
be noted that a domain configuration is not able to request a domid of “0”.
Beyond that, a domain node may have any of the following optional properties.

Properties
""""""""""

compatible
  Identifies the node as a domain node and for which hypervisor. Required.

  Format: "<hypervisor name>,domain", e.g "xen,domain"

domid
  Identifies the domid requested to assign to the domain.

  Format: Integer, e.g <0>

role
  This sets what Discretionary Access Control permissions
  a domain is assigned. Optional, default is none.

  Format: Bitfield, e.g <3> or <0x00000003>

          ROLE_NONE                (0)
          ROLE_UNBOUNDED_DOMAIN    (1U<<0)
          ROLE_CONTROL_DOMAIN      (1U<<1)
          ROLE_HARDWARE_DOMAIN     (1U<<2)
          ROLE_XENSTORE_DOMAIN     (1U<<3)

capability
  This identifies what system capabilities a domain may have beyond the role it
  was assigned.
  Optional, the default is none.

  Format: Bitfield, e.g <3221225487> or <0xC0000007>

          CAP_NONE            (0)
          CAP_CONSOLE_IO      (1U<<0)

mode
  The mode the domain will be executed under. Required.

  Format: Bitfield, e.g <5> or <0x00000005>

          MODE_PARAVIRTUALIZED     (1 << 0) PV | PVH/HVM
          MODE_ENABLE_DEVICE_MODEL (1 << 1) HVM | PVH
          MODE_LONG                (1 << 2) 64 BIT | 32 BIT

domain-uuid
  A globally unique identifier for the domain. Optional,
  the default is NULL.

  Format: Byte Array, e.g [B3 FB 98 FB 8F 9F 67 A3]

cpus
  The number of vCPUs to be assigned to the domain. Optional,
  the default is “1”.

  Format: Integer, e.g <0>

memory
  The amount of memory to assign to the domain, in KBs. This field uses a DTB
  Reg which contains a start and size. For memory allocation start may or may
  not have significance but size will always be used for the amount of memory
  Required.

  Format: String  min:<sz> | max:<sz> | <sz>, e.g. "256M"

security-id
  The security identity to be assigned to the domain when XSM
  is the access control mechanism being used. Optional,
  the default is “system_u:system_r:domU_t”.

  Format: string, e.g. "system_u:system_r:domU_t"

Child Nodes
"""""""""""

* module

Module node
-----------

This node describes a boot module loaded by the boot loader. A ``module`` node
will often appear repeatedly and will require a unique and DTB compliant name
for each instance. The compatible property is required to identify that the
node is a ``module`` node, the type of boot module, and what it represents.

Depending on the type of boot module, the ``module`` node will require either a
``module-index`` or ``module-addr`` property must be present. They provide the
boot module specific way of locating the boot module in memory.

Properties
""""""""""

compatible
  This identifies what the module is and thus what the hypervisor
  should use the module for during domain construction. Required.

  Format: "module,<module type>"[, "module,<locating type>"]
          module type: kernel, ramdisk, device-tree, microcode, xsm-policy,
                       config

          locating type: index, addr

module-index
  This identifies the index for this module when in a module chain.
  Required for multiboot environments.

  Format: Integer, e.g. <0>

module-addr
  This identifies where in memory this module is located. Required for
  non-multiboot environments.

  Format: DTB Reg <start size>, e.g. <0x0 0x20000>

bootargs
  This is used to provide the boot params to kernel modules.

  Format: String, e.g. "ro quiet"

.. note::  The bootargs property is intended for situations where the same kernel multiboot module is used for more than one domain.

Example Configuration
---------------------

Below are two example device tree definitions for the hypervisor node. The
first is an example of a multiboot-based configuration for x86 and the second
is a module-based configuration for Arm.

Multiboot x86 Configuration:
""""""""""""""""""""""""""""

::

    /dts-v1/;

    / {
        chosen {
            hypervisor {
                compatible = "hypervisor,xen", "xen,x86";

                dom0 {
                    compatible = "xen,domain";

                    domid = <0>;

                    role = <9>;
                    mode = <12>;

                    domain-uuid = [B3 FB 98 FB 8F 9F 67 A3 8A 6E 62 5A 09 13 F0 8C];

                    cpus = <1>;
                    memory = "1024M";

                    kernel {
                        compatible = "module,kernel", "module,index";
                        module-index = <1>;
                    };

                    initrd {
                        compatible = "module,ramdisk", "module,index";
                        module-index = <2>;
                    };
                };

                dom1 {
                    compatible = "xen,domain";
                    domid = <1>;
                    role = <0>;
                    capability = <1>;
                    mode = <12>;
                    domain-uuid = [C2 5D 91 CB 60 4B 45 75 89 04 FF 09 64 54 1A 74];
                    cpus = <1>;
                    memory = "1024M";

                    kernel {
                        compatible = "module,kernel", "module,index";
                        module-index = <3>;
                        bootargs = "console=hvc0 earlyprintk=xen root=/dev/ram0 rw";
                    };

                    initrd {
                        compatible = "module,ramdisk", "module,index";
                        module-index = <4>;
                    };
                };
            };
        };
    };



The multiboot modules supplied when using the above config would be, in order:

* (the above config, compiled)
* kernel for PVH unbounded domain
* ramdisk for PVH unbounded domain
* kernel for PVH guest domain
* ramdisk for PVH guest domain

Module Arm Configuration:
"""""""""""""""""""""""""

::

    /dts-v1/;

    / {
        chosen {
            hypervisor {
                compatible = “hypervisor,xen”

                // Configuration container
                config {
                    compatible = "xen,config";

                    module {
                        compatible = "module,xsm-policy";
                        module-addr = <0x0000ff00 0x80>;

                    };
                };

                // Unbounded Domain definition
                dom0 {
                    compatible = "xen,domain";

                    domid = <0>;

                    role = <9>;

                    mode = <12>; /* 64 BIT, PVH */

                    memory = <0x0 0x20000>;
                    cpus = <1>;
                    module {
                        compatible = "module,kernel";
                        module-addr = <0x0000ff00 0x80>;
                    };

                    module {
                        compatible = "module,ramdisk";
                        module-addr = <0x0000ff00 0x80>;
                    };

                // Guest definition
                dom1 {
                    compatible = "xen,domain";

                    domid = <0>;

                    role = <0>;
                    capability = <1>;

                    mode = <12>; /* 64 BIT, PVH */

                    // UUID
                    domain-uuid = [C2 5D 91 CB 60 4B 45 75 89 04 FF 09 64 54 1A 74];

                    cpus = <1>;
                    memory = <0x0 0x20000>;
                    security-id = “dom0_t”;

                    module {
                        compatible = "module,kernel";
                        module-addr = <0x0000ff00 0x80>;
                        bootargs = "console=hvc0";
                    };
                    module {
                        compatible = "module,ramdisk";
                        module-addr = <0x0000ff00 0x80>;
                    };
                };
            };
        };
    };

The modules that would be supplied when using the above config would be:

* (the above config, compiled into hardware tree)
* XSM policy
* kernel for unbounded domain
* ramdisk for unbounded domain
* kernel for guest domain
* ramdisk for guest domain

The hypervisor device tree would be compiled into the hardware device tree and
provided to Xen using the standard method currently in use. The remaining
modules would need to be loaded in the respective addresses specified in the
`module-addr` property.
