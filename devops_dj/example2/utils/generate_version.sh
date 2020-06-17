VER_FILE=$BS_BUILD_DIR/utils/version.ini

#if environment var VERSION is not set, refer to version.in
if [[ -z "${VERSION}" ]]; then
    if [ -f ${VER_FILE} ]; then
        VERSION=$(grep version ${VER_FILE} | cut -d ' ' -f2 )
    else
        echo "Abort, ${VER_FILE} not exist"
        exit 1
    fi
fi

GITHASH=$( git rev-parse --short --revs-only HEAD )
GITHASH=${GITHASH:0:7}
BRANCH=$( git branch | grep \* | cut -d ' ' -f2 )
if [ "$BRANCH" == "(HEAD" ]; then
    BRANCH=$TRAVIS_BRANCH
fi
ITERATION=${GITHASH}_${BRANCH}
FINAL_VER=${VERSION}_${ITERATION}
echo $FINAL_VER
