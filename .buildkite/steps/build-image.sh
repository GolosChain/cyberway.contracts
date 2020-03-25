#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

if [[ "${BUILDKITE_BRANCH}" == "master" ]]; then
    BUILDTYPE="stable"
else
    BUILDTYPE="latest"
fi

if [[ -z ${CDT_TAG+x} ]]; then 
    CDT_TAG=${BUILDTYPE}
    docker pull cyberway/cyberway.cdt:${CDT_TAG}
fi

if [[ -z ${CW_TAG+x} ]]; then 
    CW_TAG=${BUILDTYPE}
    docker pull cyberway/cyberway:${CW_TAG}
fi

if [[ -z ${BUILDER_TAG+x} ]]; then 
    BUILDER_TAG=${BUILDTYPE}
    docker pull cyberway/builder:${BUILDER_TAG}
fi

docker build -t cyberway/cyberway.contracts:${REVISION} --build-arg=version=${REVISION} --build-arg=cw_tag=${CW_TAG} --build-arg=cdt_tag=${CDT_TAG}  --build-arg=builder_tag=${BUILDER_TAG} --build-arg=ci_build=${CI} -f Docker/Dockerfile .
