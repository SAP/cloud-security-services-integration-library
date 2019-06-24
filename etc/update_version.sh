#!/bin/bash

pomVersion=0.0.0
if [ "$#" -eq 1 ]; then
  echo "Update com.sap.cloud.security.xsuaa version to: " $1
  pomVersion=$1
else
  echo ""
  echo "Call this script with a version, e.g. see pom.xml and use 1.n.0 (n=n+1)"
  echo "Example: ./update_version.sh 1.6.0"
  echo ""
  exit 1
fi
################################# CONFIGURATION #################################
cd ..
git remote add sec-lib-spring git@github.com:SAP/cloud-security-xsuaa-integration.git
git fetch sec-lib-spring
git checkout -B master_version sec-lib-spring/master
git reset --hard sec-lib-spring/master
git clean -d -x -f
sed -i 's/## master[\n]*$/## master\n\n## '$pomVersion'\n\n### Changed\n - \n/g' CHANGELOG.md
mvn versions:set -DgenerateBackupPoms=false -DnewVersion=$pomVersion
mvn clean install -DskipTests=true -Dmaven.test.skip=true
cd spring-xsuaa-it
mvn versions:set -DgenerateBackupPoms=false -DnewVersion=$pomVersion
cd ..
git commit -a -m "com.sap.cloud.security.xsuaa version $pomVersion"
git push sec-lib-spring HEAD:master_version
echo "Version $pomVersion created, start PR from master_version"
echo ""

