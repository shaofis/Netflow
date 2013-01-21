Netflow
=============

Is a netflow parser for node.js

Installation
============

npm install https://github.com/shaofis/Netflow/tarball/master

Basic Example
=============

    var NetFlowPacket = require('./NetFlowPacket')
    var dgram = require('dgram')

    var server = dgram.createSocket('udp4');
    server.on('message', function(msg, rinfo){
      var Packet = new NetFlowPacket(msg, rinfo.address);
      console.log(Packet)
    });
    server.bind(2055);

Status
======

V9 Appears to be working; needs more testing.
I'm close on V10 but it isn't complete yet; I have been working with rfc5101 but I believe there is a newer version. 
For now V10 is handled with a few exceptions based on changes from a newer rfc.
      
I've changed NetFlowPacket to return an object including the header and 3 key arrays

        Flows[]            mapped flows
        Templates[]        received templates
        noTemplates[]      flow information where we don't yet have a template for
    
Templates are sent so that you can store it semi permanantly so that on reload you can immediatly decode these flows.
Since we can't decode a V9 or V10 packet until we have a template I've sent those packets back to the main app where you can decide if you want to queue it and decode it later or discard it.
    
Origin
======

This is a fork of Node-Netflowd by Sharif Ghazzawi
https://github.com/Sghazzawi/Node-Netflowd/
