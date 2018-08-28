#!/bin/bash
# GDM Wallpaper
# v1

gdmw(){

	path=/mnt/data/media/gdm
	img=$1

	cd /root/gnome-shell-js/
	mkdir -p ui/components ui/status misc perf extensionPrefs gdm theme

	gs=/usr/share/gnome-shell/gnome-shell-theme.gresource
	for r in `gresource list $gs`; do
		gresource extract $gs $r > ${r/#\/org\/gnome\/shell/.}
	done

	yes |cp -rf /usr/share/gnome-shell/gnome-shell-theme.gresource .
	touch gnome-shell-theme.gresource.xml
	echo '<?xml version="1.0" encoding="UTF-8"?>' >> gnome-shell-theme.gresource.xml
	echo "<gresources>" >> gnome-shell-theme.gresource.xml
	echo '<gresource prefix="/org/gnome/shell/theme">' >> gnome-shell-theme.gresource.xml
	gresource list gnome-shell-theme.gresource >> gnome-shell-theme.gresource.xml
	echo "</gresource>" >> gnome-shell-theme.gresource.xml
	echo "</gresources>" >> gnome-shell-theme.gresource.xml
	sed 's/\/org\/gnome\/shell\/theme\//\<file>/g' gnome-shell-theme.gresource.xml > gnome-1.xml
	sed 's/.svg/.svg\<\/file>/g' gnome-1.xml > gnome-2.xml
	sed 's/.png/.png\<\/file>/g' gnome-2.xml > gnome-1.xml
	sed 's/.css/.css\<\/file>/g' gnome-1.xml > gnome-shell-theme.gresource.xml
	rm -rfv gnome-[1-2].xml

	# sed
	nano gnome-shell-theme.gresource.xml
	mv -fv gnome-shell-theme.gresource.xml theme
	cd theme/
	# sed
	nano gnome-shell.css

	yes | cp -rf $path/$img $PWD
	glib-compile-resources gnome-shell-theme.gresource.xml
	cd /usr/share/gnome-shell
	mv -vf gnome-shell-theme.gresource gnome-shell-theme.gresource.bu
	yes | cp -rf $HOME/gnome-shell-js/theme/gnome-shell-theme.gresource .

}
gdmw $1

