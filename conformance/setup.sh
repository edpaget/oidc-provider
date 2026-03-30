#!/usr/bin/env bash
# Sets up and starts the OpenID Conformance Suite for testing.
#
# Usage: ./conformance/setup.sh
#
# Clones the conformance suite repo (if not already present), builds
# the JAR via Maven in Docker, and starts the suite via docker compose.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SUITE_DIR="$PROJECT_DIR/conformance-suite"

cd "$PROJECT_DIR"

# Clone if not present
if [ ! -d "$SUITE_DIR" ]; then
  echo "Cloning conformance suite..."
  git clone --depth 1 https://gitlab.com/openid/conformance-suite.git "$SUITE_DIR"
fi

# Build if JAR not present
if [ ! -f "$SUITE_DIR/target/fapi-test-suite.jar" ]; then
  echo "Building conformance suite (this may take a few minutes)..."
  MAVEN_CACHE="$SUITE_DIR/m2" docker compose -f "$SUITE_DIR/builder-compose.yml" run builder
fi

# Start services
echo "Starting conformance suite..."
docker compose up -d

echo ""
echo "Conformance suite starting at https://localhost.emobix.co.uk:8443/"
echo "Wait ~30 seconds for the Java server to initialize."
echo ""
echo "Next steps:"
echo "  1. Start the dev server:    clojure -M:dev"
echo "  2. Run conformance tests:   clojure -M:conformance"
