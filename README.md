# logmon - Real-time Syslog Log Monitor

## Installation

Install Ubuntu 14.04, don't install any optional packages, except OpenSSH package if needed for remote access

```
sudo apt-get install node npm git
git clone git@github.com:utahsaint-org/logmon.git
cd logmon
npm install
```

Edit `conf/logmon.conf` to set the correct paths.

Make sure the last line of `logmon.upstart` has the correct path to `app.js`. Edit if necessary.

```
sudo cp logmon.upstart /etc/init/logmon.conf
sudo service logmon start
```

Verify that logmon has successfully started.

```
sudo service logmon status
```

Go to http://*&lt;host&gt;* and you will see a list of log channels to display.
