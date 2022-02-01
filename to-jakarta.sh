#!/usr/bin/env bash

# move to jakarta parent
find . -type f -name 'pom.xml' -exec sed -i '' 's/smallrye-parent/smallrye-jakarta-parent/g' {} +
# java sources
find . -type f -name '*.java' -exec sed -i '' 's/javax./jakarta./g' {} +
find . -type f -name '*.java' -exec sed -i '' 's/jakarta.crypto./javax.crypto./g' {} +
find . -type f -name '*.java' -exec sed -i '' 's/jakarta.security.auth./javax.security.auth./g' {} +
# service loader files
find . -path "*/src/main/resources/META-INF/services/javax*" | sed -e 'p;s/javax/jakarta/g' | xargs -n2 git mv

mvn build-helper:parse-version versions:set -DnewVersion=\${parsedVersion.nextMajorVersion}.0.0-SNAPSHOT -Pcoverage

mvn versions:update-property -Dproperty=version.jakarta.servlet.api -DnewVersion=[5.0.0] -N
mvn versions:update-property -Dproperty=version.jakarta.security.enterprise.api -DnewVersion=[2.0.0] -N
mvn versions:update-property -Dproperty=version.smallrye.config -DnewVersion=[3.0.0-RC1] -N
mvn versions:update-property -Dproperty=version.eclipse.microprofile.jwt -DnewVersion=[2.0] -N
mvn versions:update-property -Dproperty=version.microprofile.config -DnewVersion=[3.0] -N
mvn versions:set-property -Dproperty=artifactId.arquillian.jetty -DnewVersion=arquillian-jetty-embedded-11 -N
mvn versions:set-property -Dproperty=version.arquillian.jetty -DnewVersion=1.0.0.CR4 -N
mvn versions:update-property -Dproperty=version.jetty -DnewVersion=[11.0.7] -N
mvn versions:set-property -Dproperty=version.resteasy -DnewVersion=6.0.0.Final -N
mvn versions:set-property -Dproperty=groupId.resteasy.client -DnewVersion=org.jboss.resteasy.microprofile -N
mvn versions:set-property -Dproperty=artifactId.resteasy.client -DnewVersion=microprofile-rest-client -N
mvn versions:set-property -Dproperty=version.resteasy.client -DnewVersion=2.0.0.Beta1 -N
