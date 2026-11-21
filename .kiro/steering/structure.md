---
title: Structure
inclusion: always
---

# Repository structure

```
antikythera/
├── .kiro/
│   ├── steering/          product, tech, structure, coding and test standards
│   └── specs/<name>/      requirements.md, design.md, tasks.md per major piece
├── cmake/                 Vcpkg, CompilerLauncher, Warnings, Hardening, Sanitizers
├── src/
│   ├── common/            ak::wire and other role-independent helpers
│   ├── helm/              control-plane role (ak::helm)
│   ├── hull/              host agent (ak::hull)                    [planned]
│   ├── hold/              network volume storage role (ak::hold)   [designed]
│   ├── oar/
│   │   ├── net/           network data plane (ak::oar::net)
│   │   ├── blk/           storage data plane (ak::oar::blk)
│   │   ├── gpu/           GPU data plane (ak::oar::gpu)            [designed]
│   │   ├── virtio/        shared virtio device core (ak::oar::virtio)
│   │   ├── vfu/           libvfio-user adapter (harbor transport)
│   │   └── testdev/       phase-1 vfio-user test device
│   └── proto/             helm<->controller protocols (ak::proto); helm<->oar [planned]
├── tests/                 Boost.Test, one executable per file, run with ctest
├── fuzz/                  libFuzzer target per untrusted-input parser
├── harbor/                virt-on-virt environment: scripts, kernel configs, topologies
├── vcpkg.json, vcpkg-configuration.json, vcpkg-overlays/
├── DEPENDENCIES.md
└── docs/
```

## Rules

- **Roles never include each other's internals.** `helm`, `hull` and each
  `oar` talk only through the protocols in `src/proto/` and `helm/mailbox`.
  A role must build and test on its own.
- **One transport seam per device.** Device logic is written once against
  `oar/virtio` and bound to a transport: vfio-user in harbor, Linux
  `pci-epf` on hardware.
- **Every untrusted-input parser** has unit tests, a fuzz target, and returns
  `std::expected`.
- **Spec references in code** use the form `.kiro/specs/<name>/` Requirement N,
  as kythira does.
- **Copyright header** on every new file that can carry a comment
  (Apache-2.0, see CLAUDE.md); none on JSON, Markdown, vendored or
  generated files.
