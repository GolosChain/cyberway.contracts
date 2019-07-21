#/bin/bash

set -euo pipefail

cd Docker

docker-compose down
docker volume rm cyberway-system-mongodb-data || true
docker volume create --name=cyberway-system-mongodb-data

IMAGETAG=${BUILDKITE_BRANCH:-master}

docker-compose up -d

# Run unit-tests
sleep 10s
docker run --network cyberway-tests_contracts-net -ti cyberway/cyberway.contracts:$IMAGETAG  /bin/bash -c 'export MONGO_URL=mongodb://mongo:27017; /opt/cyberway.contracts/unit_test -l message -r detailed'
result=$?

docker-compose down

exit $result
