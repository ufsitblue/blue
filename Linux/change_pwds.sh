# Change passwords.
# TODO: generate CSVs for the password changes according to the specified format (https://anonymfile.com/6Q6D/seccdc-24-team-packet.pdf)

host=$(hostname)
adminUsers=("elara.boss" "sarah.lee" "lisa.brown" "michael.davis" "emily.chen" "tom.harris" "bob.johnson" "david.kim" "rachel.patel" "dave.grohl" "kate.skye" "leo.zenith" "jack.rover")
normalUsers=("lucy.nova" "xavier.blackhole" "ophelia.redding" "marcus.atlas" "yara.nebula" "parker.posey" "maya.star" "zachary.comet" "quinn.jovi" "nina.eclipse" "alice.bowie" "ruby.rose" "owen.mars" "bob.dylan" "samantha.stephens" "parker.jupiter" "carol.rivers" "taurus.tucker" "rachel.venus" "emily.waters" "una.veda" "ruby.starlight" "frank.zappa" "ava.stardust" "samantha.aurora" "grace.slick" "benny.spacey" "sophia.constellation" "harry.potter" "celine.cosmos" "tessa.nova" "ivy.lee" "dave.marsden" "thomas.spacestation" "kate.bush" "emma.nova" "una.moonbase" "luna.lovegood" "frank.astro" "victor.meteor" "mars.patel" "grace.luna" "wendy.starship" "neptune.williams" "henry.orbit" "ivy.starling")

# Change password for administrative users
for user in "${adminUsers[@]}"; do
    # Check if user exists
    if id $user &>/dev/null
        # Generate a random password for each user
        pword=$(head -c 100 /dev/urandom | tr -dc 'a-zA-Z0-9@#$%&!?:*-+=' | cut -c1-23)

        # Change password and echo to std output for use in csv file
        echo "${user}:${pword}" | chpasswd > /dev/null
        echo "${host}-ssh,${user},${pword}"
    fi
done

# Change password for normal users
for user in "${normalUsers[@]}"; do
    # Check if user exists
    if id $user &>/dev/null
        # Generate a random password for each user
        pword=$(head -c 100 /dev/urandom | tr -dc 'a-zA-Z0-9@#$%&!?:*-+=' | cut -c1-23)

        # Change password and echo to std output for use in csv file
        echo "${user}:${pword}" | chpasswd > /dev/null
        echo "${host}-ssh,${user},${pword}"
    fi
done
echo "Passwords successfully changed.  Paste this into Team19_${host}-ssh_PWD and submit to black team"
