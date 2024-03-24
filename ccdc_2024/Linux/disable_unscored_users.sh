#!/bin/bash

usersToKeep=(
    "elara.boss" "sarah.lee" "lisa.brown" "michael.davis" "emily.chen"
    "tom.harris" "bob.johnson" "david.kim" "rachel.patel" "dave.grohl"
    "kate.skye" "leo.zenith" "jack.rover" "lucy.nova" "xavier.blackhole"
    "ophelia.redding" "marcus.atlas" "yara.nebula" "parker.posey" "maya.star"
    "zachary.comet" "quinn.jovi" "nina.eclipse" "alice.bowie" "ruby.rose"
    "owen.mars" "bob.dylan" "samantha.stephens" "parker.jupiter" "carol.rivers"
    "taurus.tucker" "rachel.venus" "emily.waters" "una.veda" "ruby.starlight"
    "frank.zappa" "ava.stardust" "samantha.aurora" "grace.slick" "benny.spacey"
    "sophia.constellation" "harry.potter" "celine.cosmos" "tessa.nova" "ivy.lee"
    "dave.marsden" "thomas.spacestation" "kate.bush" "emma.nova" "una.moonbase"
    "luna.lovegood" "frank.astro" "victor.meteor" "mars.patel" "grace.luna"
    "wendy.starship" "neptune.williams" "henry.orbit" "ivy.starling" "seccdc_black"
)

for userDir in /home/*; do
  userName=$(basename "$userDir")
  if [[ ! " ${usersToKeep[@]} " =~ " ${userName} " ]]; then
    # Comment out the user in /etc/passwd
	  sudo sed -i "s/^${userName}/^#${userName}/g" /etc/passwd
    echo "User: ${userName} disabled"    
  fi
done

