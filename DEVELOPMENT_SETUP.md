Install java

`sudo apt install default-jdk`

Clone logstash

`git clone https://github.com/elastic/logstash.git`

Build

`cd  logstash`

`./gradlew assemble`

`rake bootstrap`

Git clone plugin

`git clone https://github.com/xucito/logstash-output-spoof.git`

`cd logstash-output-spoof`

Create a gradle.properties file with 

`LOGSTASH_CORE_PATH=<path to where you cloned logstash>/logstash-core`

Install Ruby Bundler

`apt install ruby-bundler`

Assemble

`./gradlew assemble`
