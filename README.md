# Logstash Java Plugin

[![Travis Build Status](https://travis-ci.org/logstash-plugins/logstash-output-java_output_example.svg)](https://travis-ci.org/logstash-plugins/logstash-output-java_output_example)

This is a Java plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are free to use it however you want.

The documentation for Logstash Java plugins is available [here](https://www.elastic.co/guide/en/logstash/6.7/contributing-java-plugin.html).

## Usage

The plugin uses http://jnetpcap.sourceforge.net/docs/jnetpcap-1.0-javadoc/org/jnetpcap/Pcap.html

Download: https://sourceforge.net/projects/jnetpcap/files/jnetpcap/Latest/jnetpcap-1.4.r1425-1.win64.zip/download

You can check the release notes for instructions on installation

Tested using Ubuntu 16.04 and 18.04

`wget -O jnetpcap-1.4.r1425 https://downloads.sourceforge.net/project/jnetpcap/jnetpcap/Latest/jnetpcap-1.4.r1425-1.linux64.x86_64.tgz`

`tar -xvf jnetpcap-1.4.r1425`

`cp jnetpcap-1.4.r1425/libjnetpcap.so /lib/`

## Write up

A detailed walk through of usage can be found [here](https://tonysbit.blog/2019/10/05/spoofing-udp-traffic-with-logstash/)

## Sample config

```
input {
  generator { message => "Hello world!" count => 1 }
}
filter {
  mutate {
   add_field => {
      "extra_field" => "this is the test field"
      "src_host" => "3.3.3.3"
   }
   update => {"message" => "this should be the new message"}
  }
}
output {
  spoof {
    dest_host => "<REPLACE WITH YOUR DESTINATION IP>"
    dest_port => "<REPLACE WITH YOUR DESTINATION PORT>"
    src_host => "%{src_host}"
    src_port => "2222"
    dest_mac =>  "<REPLACE WITH YOUR DESTINATION MAC ADDRESS>"
    src_mac => "<REPLACE WITH YOUR MAC ADDRESS>"
    message => "%{message}"
    interface => "ens32"
  }
}
```
