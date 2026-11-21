// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// An image store as ak-oar-blk is configured with it (.kiro/specs/
// oar-blk-data-plane/ task 13): one file per store, named on the command
// line as --image-store ID=PATH. The ID is what helm's create_volume names;
// the file says where the store is and how to reach it:
//
//   # comments and blank lines are ignored
//   endpoint   = https://minio.example:9000   # http:// or https://; host or [IPv6]
//   bucket     = images
//   prefix     = base                         # optional; keys are <prefix>/<name>/...
//   region     = us-east-1                    # optional (default us-east-1)
//   style      = path                         # optional: path (default) or virtual
//   ca_file    = /etc/ak/store-ca.pem         # optional; default the system trust store
//   access_key = ...                          # optional, with secret_key; none: anonymous
//   secret_key = ...
//
// Every key at most once; anything else is an error naming the line. The
// credentials should be read-only and scoped to the bucket (Requirement
// 8.9); a file holding a secret must not be readable by group or others,
// which ak-oar-blk checks before parsing.
//
// The file is the operator's, not untrusted input: the parser is strict so
// that a typo fails at start-up rather than at the first attach.

#include <expected>
#include <string>
#include <string_view>

#include "oar/blk/s3_object_store.hpp"

namespace ak::oar::blk {

struct ImageStoreConfig {
    S3Config s3;
    std::string prefix;
};

// The parsed file, or a message naming the offending line.
[[nodiscard]] auto parse_image_store_config(std::string_view text)
    -> std::expected<ImageStoreConfig, std::string>;

}  // namespace ak::oar::blk
