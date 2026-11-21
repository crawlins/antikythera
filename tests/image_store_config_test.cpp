// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ task 13: the image store files
// ak-oar-blk reads. Every key parses, defaults hold, comments and blank
// lines are skipped, and anything unknown, repeated or malformed is an
// error naming its line.

#define BOOST_TEST_MODULE image_store_config_test
#include <boost/test/unit_test.hpp>

#include <string>
#include <string_view>

#include "oar/blk/image_store_config.hpp"

namespace blk = ak::oar::blk;

BOOST_AUTO_TEST_SUITE(image_store_config)

BOOST_AUTO_TEST_CASE(parses_every_key) {
    const auto c = blk::parse_image_store_config(
        "# the base images\n"
        "endpoint = https://minio.example:9000\n"
        "\n"
        "  bucket=images   # trailing comment\n"
        "prefix = base/v1\n"
        "region = eu-west-2\n"
        "style = virtual\n"
        "ca_file = /etc/ak/ca.pem\n"
        "access_key = AKID\n"
        "secret_key = se#cret/key\n");
    BOOST_REQUIRE(c.has_value());
    BOOST_TEST(c->s3.tls);
    BOOST_TEST(c->s3.host == "minio.example");
    BOOST_TEST(c->s3.port == 9000);
    BOOST_TEST(c->s3.bucket == "images");
    BOOST_TEST(c->prefix == "base/v1");
    BOOST_TEST(c->s3.region == "eu-west-2");
    BOOST_TEST(!c->s3.path_style);
    BOOST_TEST(c->s3.ca_file == "/etc/ak/ca.pem");
    BOOST_REQUIRE(c->s3.credentials.has_value());
    BOOST_TEST(c->s3.credentials->access_key == "AKID");
    BOOST_TEST(c->s3.credentials->secret_key == "se#cret/key");  // '#' inside a value
}

BOOST_AUTO_TEST_CASE(defaults_and_endpoint_forms) {
    auto c = blk::parse_image_store_config("endpoint = http://10.0.0.5\nbucket = b\n");
    BOOST_REQUIRE(c.has_value());
    BOOST_TEST(!c->s3.tls);
    BOOST_TEST(c->s3.host == "10.0.0.5");
    BOOST_TEST(c->s3.port == 0);  // the scheme's default
    BOOST_TEST(c->s3.region == "us-east-1");
    BOOST_TEST(c->s3.path_style);
    BOOST_TEST(c->prefix.empty());
    BOOST_TEST(!c->s3.credentials.has_value());  // anonymous

    c = blk::parse_image_store_config("endpoint = https://[fd00::5]:8333\r\nbucket = b\r\n");
    BOOST_REQUIRE(c.has_value());
    BOOST_TEST(c->s3.host == "fd00::5");
    BOOST_TEST(c->s3.port == 8333);
}

BOOST_AUTO_TEST_CASE(refuses_mistakes) {
    const auto error = [](std::string_view text) {
        const auto c = blk::parse_image_store_config(text);
        BOOST_REQUIRE(!c.has_value());
        return c.error();
    };
    BOOST_TEST(error("bucket = b\n") == "no endpoint");
    BOOST_TEST(error("endpoint = https://h\n") == "no bucket");
    BOOST_TEST(error("endpoint = https://h\nbucket = b\nbuckett = c\n") ==
               "line 3: unknown key buckett");
    BOOST_TEST(error("endpoint = https://h\nbucket = b\nbucket = c\n") ==
               "line 3: bucket given twice");
    BOOST_TEST(error("endpoint = https://h\nbucket\n") == "line 2: expected key = value");
    BOOST_TEST(error("endpoint = https://h\nbucket =\n") == "line 2: bucket has no value");
    BOOST_TEST(error("endpoint = https://h\nbucket = b\nstyle = dns\n") ==
               "line 3: style is path or virtual");
    BOOST_TEST(error("endpoint = https://h\nbucket = b\naccess_key = a\n") ==
               "access_key and secret_key go together");
    for (const std::string_view bad :
         {"ftp://h", "h:9000", "https://", "https://h:0", "https://h:70000", "https://h:x",
          "https://h/path", "https://[fd00::1", "https://[]:80", "https://[fd00::1]x",
          "https://user@h"}) {
        const std::string text = std::string{"endpoint = "} + std::string{bad} + "\nbucket = b\n";
        BOOST_TEST(error(text).starts_with("line 1: endpoint is"), bad);
    }
}

BOOST_AUTO_TEST_SUITE_END()
