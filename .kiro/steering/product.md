---
title: Product
inclusion: always
---

# Antikythera — product steering

Antikythera is the hardware side of a private cloud whose API layer is
[kythira](https://github.com/crawlins/kythira). A kythira service module
implements the EC2 API; antikythera is what actually runs the instances.

## What it is

A VM host whose hypervisor does as little as possible. Every device a guest
sees — network, storage, later GPU — is a real PCIe function supplied by a
**data-plane** role on a backplane and passed straight through to the guest.
A **control-plane** role on the same backplane owns policy, keys and device
assignment, and talks to the host over a DMA-free PCIe mailbox. The host has
no IP stack, no device emulation and no device drivers beyond `vfio-pci`.

## Goals, in priority order

1. **Smallest host attack surface and resource use.** The host partitions
   CPU, memory, the IOMMU and interrupts. It emulates no devices.
2. **Untrusted devices are contained.** A compromised data-plane board, or a
   guest that controls its device, cannot reach host memory, other guests or
   other VPCs. The IOMMU, ACS and per-slot sideband isolation enforce this.
3. **Dynamic lifecycle.** VMs, devices, volumes and VPCs are created and
   destroyed at runtime. Physical inventory is fixed at boot.
4. **Portable.** x86-64 first; Arm64 later without redesign.

## Threat model

| | Status |
|---|---|
| Trusted | The minimal host (kernel, agent, VMM jails); the control-plane role and its secure element |
| Untrusted, contained | Guests; data-plane boards and functions; GPU/storage manager VMs |
| Authenticated | Operator/controller commands (signed, verified by the host agent) |
| Out of scope (for now) | Protecting guests from the host (confidential VMs); physical attacks on a running system |

Encryption at rest is still in scope: it protects pulled or decommissioned
media and gives crypto-erase.

## Naming

| Name | Meaning |
|---|---|
| **hull** | The minimal host image and its agent |
| **helm** | The control-plane role (mailbox, keys, policy, device pool) |
| **oar** | A data-plane role (`oar-net`, `oar-blk`, later `oar-gpu`) |
| **hold** | The storage-server role that keeps replicated network volumes |
| **harbor** | The virt-on-virt prototype environment |

## Order of work

Network and storage are implemented first. GPU is designed in (pool states,
protocol message types, backplane provisions) and built later. Everything is
proven in harbor before any hardware is designed.
