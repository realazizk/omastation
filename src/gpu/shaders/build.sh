#!/bin/sh
# Compiles the compute shaders to the SPIR-V that src/gpu embeds (needs glslc from shaderc).
set -e
cd "$(dirname "$0")"
for s in *.comp; do glslc --target-env=vulkan1.2 -O -o "${s%.comp}.spv" "$s"; done
