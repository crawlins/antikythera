# Implementation Plan — oar-blk: the storage data plane

## Status: 9/16 tasks complete

## Tasks

- [x] 1. XtsCipher wrapper with IEEE 1619 vectors. _Requirements: 2.1, 7.1_
  — `src/oar/blk/xts_cipher.*`: OpenSSL `aes-256-xts` over 512-byte or
  4 KiB data units, tweak = data unit number; tests carry IEEE 1619
  vectors 10-14 and 4 KiB cross-checks.
- [x] 2. KeySlot with zeroization, locked memory, no core dumps.
  _Requirements: 2.2, 2.3_
  — `src/oar/blk/key_slot.*`: one key per slot in its own page, mlocked,
  `MADV_DONTDUMP` and `MADV_WIPEONFORK`, wiped with `OPENSSL_cleanse` on
  drop and destruction; `harden_process()` sets `RLIMIT_CORE` 0 and
  `PR_SET_DUMPABLE` 0. Tests check the page flags in `/proc/self/smaps`.
- [x] 3. virtio-blk request parser with bounds checks and fuzz target.
  _Requirements: 6_
  — `src/oar/blk/request_parser.*`: IN, OUT, FLUSH and GET_ID over any
  descriptor layout (header copied out once); shape, block-size length
  and alignment, overflow-safe sector range, seg_max and transfer caps;
  UNSUPP for other types. `fuzz/fuzz_blk_request.cpp` checks that
  accepted I/O stays inside the volume and parsing never writes.
- [x] 4. VirtioBlkFunction on the shared virtio core (vfio-user).
  _Requirements: 1_
  — `src/oar/blk/virtio_blk_function.*`: a `virtio::Device` behind the
  shared `PciFunction` seam (so the vfio-user binding from oar-net task 6
  serves it unchanged). Read-only `virtio_blk_config`; IN/OUT through a
  per-queue bounce buffer (plaintext copied once, encrypted in place,
  only ciphertext reaches the `BlockBackend`; reads wiped after use);
  FLUSH, GET_ID; per-queue budget with `poll()`. Key in a `KeySlot` plus
  one `XtsCipher` per queue; FLR and `drop_key` wipe both, a driver reset
  keeps them. `fuzz/fuzz_virtio_blk.cpp` drives it as a hostile guest
  and checks every backend access stays inside the volume. The
  `ak-oar-blk` vfio-user server comes with the file backend (task 5).
- [x] 5. File backend with volume metadata header. _Requirements: 3.1_
  — `src/oar/blk/file_backend.*`: one sparse file per volume, a 4 KiB
  header (magic, version, IDs, capacity, block size, opaque wrapped key,
  SHA-256) then the ciphertext. Header decoded with `ak::wire` as
  untrusted input (`fuzz/fuzz_volume_metadata.cpp`, re-encode check).
  Files are created `O_EXCL` 0600, opened `O_NOFOLLOW`, size-checked;
  `rewrap` rewrites owner and key only; `erase` wipes the header, syncs
  and unlinks (the release half of DELETE_VOLUME).
- [x] 6. helm integration: create/attach/detach/delete/rewrap volume flows.
  _Requirements: 3_
  — Sideband `create_volume`, `delete_volume`, `rewrap_volume`
  (`src/helm/oar_protocol.*`, vendor types 0x08-0x0A, fuzzed in
  `fuzz_oar_link`). helm's CommandRouter stores a new volume with its
  wrapped key on the lowest blk slot (compensated by delete), delivers
  the key on ATTACH_VOLUME's ok rather than before relay (the VMM's open
  resets the function), reports a lost delivery as a `device_lost` host
  fault, and after commit erases (DELETE_VOLUME, DESTROY_VM without
  persist) or rewrites (REWRAP_VOLUME) the volume on the media.
  `VirtioBlkFunction::await_key` holds guest I/O in the rings until the
  key arrives, across the FLR. `src/oar/blk/blk_role.*` is the role's
  OarHandler over FileBackend, with one function per transport swapped
  between an empty placeholder and the attached volume;
  `ak-oar-blk` (`oar_blk_main.cpp`) serves it over vfio-user and helm's
  sideband socket (`VirtioBinding::retarget`, `set_reset_handler`).
- [ ] 7. Boot from volume in harbor. _Requirements: 4_
- [ ] 8. harbor encryption scenarios. _Requirements: 7.2_
- [x] 9. Image manifest codec, name and chunk digests, fuzz target.
  _Requirements: 8.3, 8.11_
  — `src/oar/blk/image_manifest.*` (library `ak_oar_blk_image`): encode
  and decode with every field checked (count before allocation, exact
  length, key ID set exactly when encrypted), `decode_named_manifest`
  against the image name, `chunk_matches` for fetched chunks, hex image
  names. `fuzz/fuzz_image_manifest.cpp` checks accepted manifests
  re-encode byte for byte.
- [x] 10. ObjectStore seam, ChunkCache, Fetcher with readahead,
  Overlay and LazyImageBackend over an in-memory store.
  _Requirements: 8.1-8.7, 8.10, 7.3_
  — `object_store.hpp` (thread-safe `get_range`/`get`, image object
  keys), `chunk_cache.*` (per-image `O_TMPFILE`, shared by name, one LRU
  and budget for all images, pinned reads, hole punching), `fetcher.*`
  (worker threads, demand ahead of readahead, one fetch per chunk with
  promotion, one deadline per chunk, jittered retries on io, malformed
  and corrupt responses; returns the bytes so a full cache never fails a
  read), `overlay.*` (unlinked sparse file plus bitmap, write before
  bits, limit, discard), `lazy_image_backend.*` (overlay/image/zero runs,
  K_img decrypt then K_eph encrypt, holes as plaintext zeros, readahead
  window doubling to `max_readahead_chunks`, discard on `drop_keys`).
  `tests/image_volume_test.cpp` covers each, plus a guest reading the
  image and its own writes through `VirtioBlkFunction`.
- [x] 11. S3ObjectStore: HTTP/1.1 range GET over TCP/TLS, SigV4,
  response parser with fuzz target, MinIO test.
  _Requirements: 8.2, 8.9, 8.11, 7.3_
  — library `ak_oar_blk_s3`: `sigv4.*` (checked against AWS's documented
  GET-with-Range example), `http_response.*` (strict head parser,
  `fuzz/fuzz_http_response.cpp`), `s3_object_store.*` (path or
  virtual-host style, keep-alive pool with one retry on an idle-closed
  connection, TLS 1.2+ verifying name and chain, 206 with the exact
  Content-Range or 200 with exactly the bytes, deadline on every socket
  call). `tests/s3_object_store_test.cpp` runs a loopback S3 emulator
  that verifies every signature (plain and TLS) and misbehaving servers,
  then the image volume path over S3; with `AK_S3_TEST_ENDPOINT` set it
  also seeds and reads an image on a real S3-compatible server (run
  against SeaweedFS's S3 gateway; any MinIO works the same way).
- [x] 12. `ak-image-pack`: raw image to manifest and data objects
  (optionally encrypted). _Requirements: 8.8_
- [x] 13. Image volumes through helm: CREATE_VOLUME image source,
  version-2 volume header, K_eph at attach, discard at detach.
  _Requirements: 8.6, 8.7, 3_
- [x] 14. Asynchronous miss completion in VirtioBlkFunction.
  _Requirements: 8.10_
- [ ] 15. Encrypted images: K_img wrapped in helm, delivered with K_eph.
  _Requirements: 8.8_
- [ ] 16. harbor: boot from an image volume served by MinIO.
  _Requirements: 4, 7.3_

## Deferred

- Self-encrypting NVMe behind a storage manager VM (Requirement 5).
- SPDK backend for performance.
