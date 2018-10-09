#!/bin/bash

# News Feed
# v1.0

feed(){
       	flags="$1"
        src=$PWD/etc/src

        p_reg="title type\|feed/www"
        i_reg="summary type"
        l_reg=$flags

        for i in `cat $src | grep -v "#"`
                do printf "\n# $i\n"
                curl -s $i | grep -v "$i_reg" | grep -i "$p_reg" | tail -n $l_reg | \
                sed 's/<title type=\"html\">//g' | \
                sed 's/<link rel=\"alternate\" type=\"text\/html\" href=\"/- /g' | \
                sed 's/go.theregister.com\/feed\///g' | \
                sed 's/\"\/>/">/g' | \
                sed 's/<\/title>/\n/g' | \
                sed 's/\/\">//g' | tac
        done
}

feed $1
