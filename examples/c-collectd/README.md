HowTo use this
==============

This HowTo assumes that the examples were sucessfully compiled and installed within the prefix `/usr` on your target machine.

 1. Make sure nDPId and Collectd is running.
 2. Edit `collectd.conf` usually in `/etc`.
 3. Add the lines in `plugin_nDPIsrvd.conf` to your `collectd.conf`.
    You may adapt this file depending what command line arguments you'd supplied to `nDPId`.
 4. Reload your Collectd instance.
 5. Optional: Install a http server of your choice.
    Place the files in `/usr/share/nDPId/nDPIsrvd-collectd/www` somewhere in your www root.
 6. Optional: Add `rrdgraph.sh` as cron job e.g. `0 * * * * /usr/share/nDPId/nDPIsrvd-collectd/rrdgraph.sh [path-to-the-collectd-rrd-directory] [path-to-your-dpi-wwwroot]`.
    This will run `rrdgraph.sh` once per hour. You can adjust this until it fit your needs.
