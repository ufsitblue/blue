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
        # attempt to delete the user, ignoring errors
        userdel -r "$userName" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "Deleted user: $userName"
        else
            echo "Failed to delete user: $userName"
        fi
    fi
done

