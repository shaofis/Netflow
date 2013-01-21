var templates = {};

var ipfix = require('./ipfix.js').entities;
var UInt64 = require('./UInt64.js');


/*Class to represent the fields in a netflow packet*/
module.exports = function (msg, sender) {
//console.log(source);
    'use strict';
    var flowcount,
        offset,
        flow,
        flowsetCount,
        flowset,
        currentPosition,
        templateCount,
        //template,
        fieldcount,
        field,
        msgBuffer = new Buffer(msg);

    var containsFlag = function(number, flag){
      return (number & flag) === flag;
    };


    this.header = {};
/*read in the header information common to all supported versions. Keep this in mind when adding new versions.*/
    if (msg.length > 11) {
        this.header.version = msgBuffer.readUInt16BE(0);
        //this.header.count = msgBuffer.readUInt16BE(2);
        //this.header.sys_uptime = msgBuffer.readUInt32BE(4);
        //this.header.unix_secs = msgBuffer.readUInt32BE(8);
    } else {
        console.log('Packet is ' + msg.length);
        throw new Error("Packet is " + msg.length + " bytes long, too short to be a netflow packet");
    }
/*Depending on the version and number of flows/flowsets, read in the rest of the heder and the flows/flowsets.  There should be a case for each supported version*/
    switch(this.header.version){
      case 5:
        this.header.count = msgBuffer.readUInt16BE(2);
        this.header.sys_uptime = msgBuffer.readUInt32BE(4);
        this.header.unix_secs = msgBuffer.readUInt32BE(8);


        if (msg.length > 23) {
            this.header.unix_nsecs = msgBuffer.readUInt32BE(12);
            this.header.flow_sequence = msgBuffer.readUInt32BE(16);
            this.header.engine_type = msgBuffer.readUInt8(20);
            this.header.engine_id = msgBuffer.readUInt8(21);
            this.header.sampling_interval = msgBuffer.readUInt16BE(22);
        } else {
            throw new Error("Packet is " + msg.length + " bytes long, too short to be a netflow version 5 packet");
        }
        this.v5Flows = [];
        for (flowcount = 0; flowcount < this.header.count; flowcount++) {
          offset = 24 + (flowcount * 48);
          if ((msg.length - offset) > 47) {
            flow = {};
            flow.srcaddr = [];
            flow.dstaddr = [];
            flow.nexthop = [];
            flow.srcaddr[0] = msgBuffer.readUInt8(offset);
            flow.srcaddr[1] = msgBuffer.readUInt8(offset + 1);
            flow.srcaddr[2] = msgBuffer.readUInt8(offset + 2);
            flow.srcaddr[3] = msgBuffer.readUInt8(offset + 3);
            flow.dstaddr[0] = msgBuffer.readUInt8(offset + 4);
            flow.dstaddr[1] = msgBuffer.readUInt8(offset + 5);
            flow.dstaddr[2] = msgBuffer.readUInt8(offset + 6);
            flow.dstaddr[3] = msgBuffer.readUInt8(offset + 7);
            flow.nexthop[0] = msgBuffer.readUInt8(offset + 8);
            flow.nexthop[1] = msgBuffer.readUInt8(offset + 9);
            flow.nexthop[2] = msgBuffer.readUInt8(offset + 10);
            flow.nexthop[3] = msgBuffer.readUInt8(offset + 11);
            flow.input = msgBuffer.readUInt16BE(offset + 12);
            flow.output = msgBuffer.readUInt16BE(offset + 14);
            flow.dPkts = msgBuffer.readUInt32BE(offset + 16);
            flow.dOctets = msgBuffer.readUInt32BE(offset + 20);
            flow.first = msgBuffer.readUInt32BE(offset + 24);
            flow.last = msgBuffer.readUInt32BE(offset + 28);
            flow.srcport = msgBuffer.readUInt16BE(offset + 32);
            flow.dstport = msgBuffer.readUInt16BE(offset + 34);
            flow.pad1 = msgBuffer.readUInt8(offset + 36);
            flow.tcp_flags = msgBuffer.readUInt8(offset + 37);
            flow.prot = msgBuffer.readUInt8(offset + 38);
            flow.tos = msgBuffer.readUInt8(offset + 39);
            flow.src_as = msgBuffer.readUInt16BE(offset + 40);
            flow.dst_as = msgBuffer.readUInt16BE(offset + 42);
            flow.src_mask = msgBuffer.readUInt8(offset + 44);
            flow.dst_mask = msgBuffer.readUInt8(offset + 45);
            this.v5Flows[flowcount] = flow;
              console.log(flow);
          }
        }
        break;
      case 9:
        this.header.count = msgBuffer.readUInt16BE(2);
        this.header.sys_uptime = msgBuffer.readUInt32BE(4);
        this.header.unix_secs = msgBuffer.readUInt32BE(8);
        this.header.seqence = msgBuffer.readUInt32BE(12);
        this.header.odId = msgBuffer.readUInt32BE(16);
        offset = 20;

        this.Flows = [];
        this.Templates = [];
        this.noTemplates = [];

        if (msg.length > 19) {
        } else {
          throw new Error("Packet is " + msg.length + " bytes long, too short to be a netflow version 9 packet");
        }
        for (flowsetCount = 0; flowsetCount < this.header.count; flowsetCount++) {
          flowset = [];
          currentPosition = offset;
          var setId = msgBuffer.readUInt16BE(currentPosition);
          var flowsetLength = msgBuffer.readUInt16BE(currentPosition+2);
          currentPosition += 4;
          if (setId === 0){
            console.log('template');

            var templateId = msgBuffer.readUInt16BE(currentPosition)
            var fieldCount = msgBuffer.readUInt16BE(currentPosition+2)
            currentPosition += 4;

            if(templates[sender] && templates[sender][this.header.odId] && templates[sender][this.header.odId][templateId]){
              console.log('Template Exists:: Updating');
            } else if (templates[sender] && templates[sender][this.header.odId]){
              templates[sender][this.header.odId][templateId] = [];
            } else if (templates[sender]){
              templates[sender][this.header.odId] = {};
              templates[sender][this.header.odId][templateId] = [];
            } else {
              templates[sender] = {};
              templates[sender][this.header.odId] = {};
              templates[sender][this.header.odId][templateId] = [];
            }

            var offset = 4;
 
            for (var idx = 0; idx < fieldCount; idx++) {
              var typeName = msgBuffer.readUInt16BE(currentPosition);
              var typeLength = msgBuffer.readUInt16BE(currentPosition+2);
              currentPosition += 4;

                templates[sender][this.header.odId][templateId][idx] = {};
                if(ipfix['elements'][typeName]){
                  var element = ipfix['elements'][typeName];
                  var dataType = ipfix['dataTypes'][element.dataType];

                  templates[sender][this.header.odId][templateId][idx]['name'] = element.name;
                  templates[sender][this.header.odId][templateId][idx]['type'] = dataType;
                  if(dataType.key){
                    templates[sender][this.header.odId][templateId][idx]['key'] = dataType.key;
                  }

                } else {
                  templates[sender][this.header.odId][templateId][idx]['name'] = 'UNKNOWN';
                }
                templates[sender][this.header.odId][templateId][idx]['length'] = typeLength;

            }
          } else if (setId === 1){
            console.log('Options Template Record');
          } else if (setId > 255){

              if(templates && templates[sender] && templates[sender][this.header.odId][setId]){
                var flow = {};
                var moffset = 0;
                for (var fieldCount = 0; fieldCount < templates[sender][this.header.odId][setId].length; fieldCount++){
                  if (templates[sender][this.header.odId][setId][fieldCount]['key']){
                    var key = templates[sender][this.header.odId][setId][fieldCount]['key'];
                    for (var keyCount = 0; keyCount < templates[sender][this.header.odId][setId][fieldCount]['length']; keyCount++){
                      key = key.replace('%'+keyCount, msgBuffer.readUInt8(currentPosition));
                      currentPosition+=1;
                    }
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = key;
                  } else if (templates[sender][this.header.odId][setId][fieldCount]['length'] === 1){
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = msgBuffer.readUInt8(currentPosition);
                    currentPosition+=1;
                  } else if (templates[sender][this.header.odId][setId][fieldCount]['length'] === 2){
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = msgBuffer.readUInt16BE(currentPosition);
                    currentPosition+=2;
                  } else if (templates[sender][this.header.odId][setId][fieldCount]['length'] === 4){
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = msgBuffer.readUInt32BE(currentPosition);
                    currentPosition+=4;
                  } else if (templates[sender][this.header.odId][setId][fieldCount]['length'] === 8){
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = UInt64.readUInt64(msgBuffer, currentPosition, 'big');
                    currentPosition+=8;
                  } else {
                    //Need to handle all of the data types at some point.
                  }
                }
                this.Flows.push(flow);
              } else {
                //currentPosition += setLength; //Not applicable to V9
              }
          }
        }
        break;
      case 10:
        this.header.ilength = msgBuffer.readUInt16BE(2);
        this.header.export_time = msgBuffer.readUInt32BE(4);
        this.header.sequence = msgBuffer.readUInt32BE(8);
        this.header.odId = msgBuffer.readUInt32BE(12);

        this.Flows = [];
        this.Templates = [];
        this.noTemplates = [];

        if (msg.length > 19) {
        } else {
          throw new Error("Packet is " + msg.length + " bytes long, too short to be a netflow version 9 packet");
        }
        var currentPosition = 16;
        while (currentPosition < this.header.ilength) {
          var setId = msgBuffer.readUInt16BE(currentPosition);
          var setLength = msgBuffer.readUInt16BE(currentPosition+2);
          var setEnd = currentPosition + setLength;
          currentPosition += 4;

          if (setId === 2){
            //console.log('---------------------------TEMPLATE-------------------------');

            while (currentPosition < setEnd){
              var templateId = msgBuffer.readUInt16BE(currentPosition);
              var fieldCount = msgBuffer.readUInt16BE(currentPosition+2);
              currentPosition += 4;

              if(templates[sender] && templates[sender][this.header.odId] && templates[sender][this.header.odId][templateId]){
              } else if (templates[sender] && templates[sender][this.header.odId]){
                templates[sender][this.header.odId][templateId] = [];
              } else if (templates[sender]){
                templates[sender][this.header.odId] = {};
                templates[sender][this.header.odId][templateId] = [];
              } else {
                templates[sender] = {};
                templates[sender][this.header.odId] = {};
                templates[sender][this.header.odId][templateId] = [];
              }

              for (var idx = 0; idx < fieldCount; idx++) {
                var typeName = msgBuffer.readUInt16BE(currentPosition);
                var typeLength = msgBuffer.readUInt16BE(currentPosition+2);
                currentPosition +=4;

                if (typeName == 210){
                  var paddingOctets = typeLength;
                }
              
                if(containsFlag(msgBuffer[currentPosition], 128)){
                  console.log('------------bit 0 set-----------');
                }

                templates[sender][this.header.odId][templateId][idx] = {};

                if(ipfix['elements'][typeName]){
                  var element = ipfix['elements'][typeName];
                  var dataType = ipfix['dataTypes'][element.dataType];


                  templates[sender][this.header.odId][templateId][idx]['name'] = element.name;
                  templates[sender][this.header.odId][templateId][idx]['type'] =  element.dataType;
                  if(dataType.key){
                    templates[sender][this.header.odId][templateId][idx]['key'] = dataType.key;
                  }

                } else {
                  templates[sender][this.header.odId][templateId][idx]['name'] = 'UNKNOWN';
                }
                templates[sender][this.header.odId][templateId][idx]['length'] = typeLength;
              }
            this.Templates.push({ 
              sender : sender,
              odId : this.header.odId,
              templateId : templateId,
              fields : templates[sender][this.header.odId][templateId]
            })
            }
          } else if (setId === 3){
            console.log('Options Template Record');
          } else if (setId > 255){
          //console.log('---------------------------DATA RECORD-----------------------');

            while (currentPosition < setEnd){
              if(templates && templates[sender] && templates[sender][this.header.odId][setId]){
                var flow = {};
                var moffset = 0;
                for (var fieldCount = 0; fieldCount < templates[sender][this.header.odId][setId].length; fieldCount++){
                  if (templates[sender][this.header.odId][setId][fieldCount]['key']){
                    var key = templates[sender][this.header.odId][setId][fieldCount]['key'];
                    for (var keyCount = 0; keyCount < templates[sender][this.header.odId][setId][fieldCount]['length']; keyCount++){
                      key = key.replace('%'+keyCount, msgBuffer.readUInt8(currentPosition));
                      currentPosition+=1;
                    }
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = key;
                  } else if (templates[sender][this.header.odId][setId][fieldCount]['length'] === 1){
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = msgBuffer.readUInt8(currentPosition);
                    currentPosition+=1;
                  } else if (templates[sender][this.header.odId][setId][fieldCount]['length'] === 2){
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = msgBuffer.readUInt16BE(currentPosition);
                    currentPosition+=2;
                  } else if (templates[sender][this.header.odId][setId][fieldCount]['length'] === 4){
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = msgBuffer.readUInt32BE(currentPosition);
                    currentPosition+=4;
                  } else if (templates[sender][this.header.odId][setId][fieldCount]['length'] === 8){
                    flow[templates[sender][this.header.odId][setId][fieldCount]['name']] = UInt64.readUInt64(msgBuffer, currentPosition, 'big');
                    currentPosition+=8;
                  } else {
                    //Need to handle all of the data types at some point.
                  }
                }
                this.Flows.push(flow);
              } else {
                currentPosition += setLength;
              }
            }
          }

        currentPosition += paddingOctets;


        }



        break;  
    }

};
