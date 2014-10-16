var express = require('express'),
    app = express(),
    http = require('http').Server(app),
    io = require('socket.io')(http),
    fs = require('fs'),
    _ = require('underscore');

var config = readConfig('conf/logmon.conf'),
    port = config.port,
    fifoDir = config.fifoDir,
    channels = [],
    codeTypes = {};

// Set up Web routes
// Static files
app.use('/static', express.static(__dirname + '/static'));

// Main page
app.get('/', function(req, res) {
    res.sendfile('index.html');
});

// API for listing channels
app.get('/list/channels', function(req, res) {
    res.send(channels);
});

// Format arbitrary arguments for log output
function log() {
    args = Array.prototype.slice.apply(arguments);
    args.unshift((new Date()).toISOString().replace('T',' ').replace(/\.....$/, ''));
    console.log.apply({}, args)
}

// Handle websocket connections
io.on('connection', function(socket) {
    log('user', socket.id, 'connected');

    socket.volatile = true;
    socket.on('join', function(channel) {
	log('user', socket.id, 'joined channel', channel);
	socket.join(channel);
    });

    socket.on('leave', function(channel) {
	log('user', socket.id, 'left channel', channel);
	socket.leave(channel);
    });

    socket.on('disconnect', function() {
	log('user', socket.id, 'disconnected');
    });
});

// Start reading all fifos and start Web server
fs.readdir(fifoDir, function(err, files) {
    if (err) {
	console.log('Error reading', fifoDir + ':', err);
	process.exit(1);
    }
    // Create Web routes for each channel
    _.each(files, function(file) {
	var channel = file.replace('_fifo','');
	channels.push(channel);

	app.get('/' + channel, function(req, res){
	    res.sendfile(req.query.file || 'channel.html');
	});

	app.get('/' + channel + '_raw', function(req, res){
	    res.sendfile(req.query.file || 'channel.html');
	});

	// Process data from the FIFO
	function readFifo() {
	    var stream = fs.createReadStream(fifoDir + '/' + file);
	    stream
		.on('open', function() {
		    console.log('Reading from', file, 'to channel', channel);
		})
		.on('data', function(data) {
		    _.each(data.toString().split(/[\n\r]+/), function(line) {
			io.to(channel + '_raw').emit('data', { type: channel + '_raw', data: line });

			if (line.trim()) {
			    var parsed = parseLog(channel, line);
			    if (parsed) {
				io.to(channel).emit('data', parsed);
			    }
			}
		    });
		})
	        // Restart FIFO stream on error
		.on('error', function() {
		    console.log(channel, 'read stream error', arguments);
		    console.log(channel, 'closing and restarting');
		    stream.close();
		    readFifo();
		})
	        // Restart FIFO stream on end
		.on('end', function() {
		    console.log(channel, 'read stream ended, closing and restarting');
		    stream.close();
		    readFifo();
		});
	}
	readFifo();

	// Load user-defined class codes
	loadCodes(channel);
    });
    loadHosts();

    // Watch for changes to user-defined class codes, reload
    fs.watch(__dirname, { persistent: false }, function(event, file) {
	var channel = (file.match(/code\.(.+)$/) || [])[1];
	if (event == 'change' && channel) {
	    console.log('Updating codes for channel', channel);
	    loadCodes(channel);
	}
	if (event == 'change' && file == 'hosts') {
	    loadHosts();
	}
    });

    http.listen(port, function(){
	console.log('Listening on *:' + port);
    });
});

// Parse different log types
function parseLog(type, data) {
    if (type == 'network') {
	return parseNetworkLog(data);
    } else if (type == 'acs_access') {
	return parseAcsAccessLog(data);
    } else if (type == 'acs_commands') {
	return parseAcsCommandsLog(data);
    } else if (type == 'everything') {
	return parseEverythingLog(data);
    } else if (type == 'firewall') {
	return parseFirewallLog(data);
    } else {
	return { type: type, data: data };
    }
}

// Parse network log
function parseNetworkLog(data) {
    if (data.indexOf("%") < 0 || data.indexOf("SEC") >= 0) return;

    var matches = data.match(/^(\S+\s+\d+)\s+(\S+)\s+(\S+)\s+(.+)[\n\r]*$/);

    if (matches && matches.length == 5) {
	var parts = data.split(': ');
	var code = getCode('network', data);
	if (code != '__skip__') {
	    return { type: "network", date: matches[1], time: matches[2], ip: getHost(matches[3], true), msg: parts[2], 'code': code };
	}
    }
}

// Parse ACS commands log
function parseAcsCommandsLog(data) {
    if (!data.match(/CSCOacs_TACACS_Accounting.*Accounting\swith\sCommand./) ||
	data.match(/config\sscope\do_scheduled|writes/) ||
	data.match(/AVPair\=elapsed_time/) ||
	data.match(/NetworkDeviceName=sp.uen.net|Device IP Address=140.197.240.2/)) return;

    var user = (data.match(/\bUser\s*=\s*([^,\b]+)/) || [])[1];
    var device = (data.match(/\bNetworkDeviceName\s*=\s*([^,\b]+)/) || [])[1];
    var command = (data.match(/CmdSet\s*=\s*\[\s*CmdAV\s*=\s*(.+?)[\s\n\r]*(?:\<cr\>)?[\s\n\r]*\](?:,|$)/) || [])[1];
    var code = getCode('acs_commands', data);

    if (command) {
	if (data.match(/Uncommitted changes found\\, commit them before exiting/))
	    command = "Commit changes (y/n/cancel)?";

	// Shorten interface names
	command = command.replace(/HundredGig(abit)?E(thernet)?/, 'Hun');
	command = command.replace(/TenGig(abit)?E(thernet)?/, 'Ten');
	// GigabitEthernet should come after anything containing GigabitEthernet
	command = command.replace(/Gig(abit)?E(thernet)?/, 'Gig');
	command = command.replace(/Serial/, 'Ser');
	command = command.replace(/Loopback/, 'Lo');

	// Shorten commands
	command = command.replace(/^show interfaces description/, 'show int desc');
	command = command.replace(/^show interfaces ?/, 'show int ');
	command = command.replace(/^show running-config interface/, 'show run int');
	command = command.replace(/^show running-config ?/, 'show run ');
	command = command.replace(/^interface /, 'int ');
    }

    // Capture device name -> IP mappings
    var deviceName = (data.match(/NetworkDeviceName=([^,]+)/) || [])[1];
    var deviceIP = (data.match(/Device IP Address=([\d\.]+)/) || [])[1];
    if (deviceName && deviceIP) {
	updateHosts(deviceIP, deviceName);
    }

    return { type: "acs_commands", user: user, device: getHost(deviceIP) || device, command: command, code: code };
}

// Parse ACS Access log
function parseAcsAccessLog(data) {
    var user, remoteIP, port, deviceIP, device, code, raw, IPaddress;

    if (data.match(/CSCOacs_Passed_Authentications.*Passed\-Authentication\:\sAuthentication\ssucceeded/)) {
	user = (data.match(/\bUserName\s*=\s*([^,\b]+)/) || [])[1];
	remoteIP = (data.match(/\bRemote-Address\s*=\s*([^,\b]+)/) || [])[1];
	deviceIP = (data.match(/\bDevice\s+IP\s+Address\s*=\s*([^,\b]+)/) || [])[1];
	port = (data.match(/(?:^|,\s+)Port\s*=\s*(?:\/dev\/)?([^,\b]+)/) || [])[1];
	device = (data.match(/\bNetworkDeviceName\s*=\s*([^,\b]+)/) || [])[1];
	raw = data;
	code = "PASS";
    } else if (data.match(/CSCOacs_Failed_Attempt.*NOTICE\sFailed\-Attempt\:\sAuthentication\sfailed/)) {
	user = (data.match(/\bUserName\s*=\s*([^,\b]+)/) || [])[1];
	remoteIP = (data.match(/\bRemote-Address\s*=\s*([^,\b]+)/) || [])[1];
	deviceIP = (data.match(/\bDevice\s+IP\s+Address\s*=\s*([^,\b]+)/) || [])[1];
	port = (data.match(/(?:^|,\s+)Port\s*=\s*(?:\/dev\/)?([^,\b]+)/) || [])[1];
	device = (data.match(/\bNetworkDeviceName\s*=\s*([^,\b]+)/) || [])[1];
	code = "FAIL";
    } else if (data.match(/CisACS_\d+_FailedAuth.*Authen\sfailed/)) {
	user = (data.match(/\bUser-Name\s*=\s*([^,\b]+)/) || [])[1];
	IPaddress = (data.match(/\bNAS-IP-Address\s*=\s*([^,\b]+)/) || [])[1];
	code = "VPNFAIL"
    } else if (data.match(/CisACS_\d+_PassedAuth.*Authen\sOK/)) {
	user = (data.match(/\bUser-Name\s*=\s*([^,\b]+)/) || [])[1];
	IPaddress = (data.match(/\bNAS-IP-Address\s*=\s*([^,\b]+)/) || [])[1];
	code = "VPNPASS"
    }

    if (code) {
	if (code.match(/^VPN/)) {
	    return { type: "acs_access_vpn", user: user, ip_address: getHost(IPaddress, true), code: code };
	} else {
	    return { type: "acs_access", user: user, remote_ip: remoteIP, port: port, device_ip: getHost(deviceIP, true), device: device, code: code };
	}
    }
}

// Parse firewall log
function parseFirewallLog(data) {
    return { type: 'firewall', data: data };
}

// Parse everything log
function parseEverythingLog(data) {
    return { type: 'everything', data: data };
}

// Load user-defined class codes
function loadCodes(type) {
    var file = __dirname + "/code." + type;
    fs.exists(file, function(exists) {
	if (!exists) return;

	codeTypes[type] = {};

	fs.readFile(file, function(err, data) {
	    var curr;
	    _.each(data.toString().split(/[\n\r]+/), function(line) {
		line = line.replace(/\s*\#.*$/, '');
		if (line.match(/^\s*$/)) return;

		if (line.match(/^\S/)) {
		    curr = line.match(/^(\S+)/)[1];
		} else if (curr) {
		    var match = line.match(/^\s*(\S.*)$/);
		    if (match && match.length > 1) {
			codeTypes[type][match[1]] = curr;
		    }
		}
	    });
	    console.log('Loaded codes from ' + file);
	});
    });
}

//  Get the matching user-defined class code for a type & data match
function getCode(type, data) {
    var codes = codeTypes[type];
    var rtn;
    if (data && codes) {
	_.each(codes, function(v, k) {
	    if (!rtn && k !== '__default__' &&
		data.indexOf(k) >= 0) {
		rtn = v;
	    }
	});
    }
    if (!rtn) rtn = codes.__default__;
    return rtn;
}

// Handle local ip -> hostname mappings
var hostsFile = "hosts";
var hosts = {};
var noLoadHosts; // Temporarily suspend reloading hosts

// Load local ip -> hostname mappings
function loadHosts() {
    if (noLoadHosts) return;

    noLoadHosts = true; // Debounce
    var file = __dirname + "/" + hostsFile;
    fs.exists(file, function(exists) {
	if (!exists) return;

	hosts = {};
	fs.readFile(file, function(err, data) {
	    _.each(data.toString().split(/[\n\r]+/), function(line) {
		line = line.replace(/\s*\#.*$/, '');
		if (line.match(/^\s*$/)) return;

		var parts = line.split(/\s+/);
		if (parts && parts.length == 2) {
		    hosts[parts[0]] = parts[1];
		}
	    });
	    if (_.keys(hosts).length > 0) {
		noLoadHosts = false;
		console.log('Loaded ' + _.keys(hosts).length + ' hosts from ' + file);
	    }
	});
    });
}

// Save updated local ip -> hostname mappings
function saveHosts() {
    var file = __dirname + "/" + hostsFile;
    if (hosts && _.keys(hosts).length > 0) {
	var out = ['# Format: <ip address><space><host name>',
		   '# <host name> beginning with * is frozen and will not be updated',
		   ''];
	
	_.each(hosts, function (host, ip) {
	    out.push(ip + ' ' + host);
	});
	noLoadHosts = true; // Prevent hosts from being reloaded while we write it
	fs.writeFile(file, out.join('\n') + '\n', function() {
	    console.log('Saved ' + _.keys(hosts).length + ' hosts to ' + file);
	    setTimeout(function() {
		noLoadHosts = false; // Pause so we don't trigger reload from writing the file
	    }, 500);
	});
    }
}

// Add a new local ip -> hostname mapping
function updateHosts(ip, host) {
    if (!hosts[ip] || hosts[ip].indexOf('*') != 0 && host != getHost(ip)) {
	hosts[ip] = host;
	saveHosts();
	console.log('Added host', ip + ':', host);
    }
}

// Retrieve a local ip -> hostname mapping
function getHost(ip, trim) {
    var host = hosts[ip];
    if (ip && host) {
	host = host.replace(/^\*/, '');
	host = host.replace(/.uen.(net|org)/, '');
	if (trim) host = host.substr(0, 15);
    }
    return host || ip;
}

// Parse config file
function readConfig(confFile) {
    var data = fs.readFileSync(confFile).toString(),
        config = {};

    data.split(/[\n\r]+/).forEach(function(origLine) {
	line = origLine.replace(/\#.*$/, '').trim();

	if (line.match(/^\S+\s+\S+/)) {
	    var parts = line.split(/\s+/);

	    config[parts[0]] = parts[1];
	}
    });

    console.log('config', config);
    return config;
}

