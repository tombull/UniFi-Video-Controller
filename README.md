# unifi-video-controller

## Updated with some useful changes

This is forked from [pducharme/UniFi-Video-Controller](https://github.com/pducharme/UniFi-Video-Controller). There are a couple of improvements, largely adapted from [jacobalberty/unifi-docker](https://github.com/jacobalberty/unifi-docker). Firstly, you can now set ports for all of the main Unifi Video functions. Secondly, it will work with your own certificates.

## Original readme

This docker image runs the unifi-video controller on Ubuntu. Originally intended for Unraid 6.x, it should run fine anywhere.

Set your local data and videos directories in the `docker run` command. You can also specify a UID and GID for the daemon to run as.

Restart the docker, visit http://localhost:7080 or http://<ip.address>:7080/ to start the Unifi Video wizard.

# Run it
```
docker run \
        --name unifi-video \
        --cap-add DAC_READ_SEARCH \
        -p 10001:10001 \
        -p 1935:1935 \
        -p 6666:6666 \
        -p 7080:7080 \
        -p 7442:7442 \
        -p 7443:7443 \
        -p 7444:7444 \
        -p 7445:7445 \
        -p 7446:7446 \
        -p 7447:7447 \
        -v <data dir>:/var/lib/unifi-video \
        -v <videos dir>:/var/lib/unifi-video/videos \
        --tmpfs /var/cache/unifi-video \
        -e TZ=America/Los_Angeles \
        -e PUID=99 \
        -e PGID=100 \
        -e CREATE_TMPFS=no \
        -e DEBUG=1 \
        pducharme/unifi-video-controller
```

# Extra instructions for Docker for Windows
To avoid MongoDB errors that cause UniFi Video to hang at the "upgrading" screen on startup, you must create a volume (e.g. UnifiVideoDataVolume) `docker volume create UnifiVideoDataVolume` and then use that volume for /var/lib/unifi-video by changing this line:  `-v UnifiVideoDataVolume:/var/lib/unifi-video`

You can then specify a different directory for your actual video files, which do not need to be located in a docker volume. E.g. `-v D:\Recordings:/var/lib/unifi-video/videos`
