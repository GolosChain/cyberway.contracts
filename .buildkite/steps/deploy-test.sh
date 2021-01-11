#/bin/bash

set -euo pipefail

cd Docker

docker stop mongo || true
docker rm mongo || true
docker volume rm cyberway-mongodb-data || true
docker volume create --name=cyberway-mongodb-data

IMAGETAG=$(git rev-parse HEAD)

docker-compose up -d

# Run unit-tests
sleep 10s

docker pull cyberway/cyberway.contracts:$IMAGETAG
docker run --network cyberway-tests_contracts-net --rm -ti cyberway/cyberway.contracts:$IMAGETAG  /bin/bash -c 'export MONGO_URL=mongodb://mongo:27017; /opt/cyberway.contracts/unit_test -l message -r detailed'
result=$?

docker-compose down

exit $result
