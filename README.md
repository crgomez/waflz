# What is Waflz 
========

Verizon Digital Media in-house implementation of ModSecurity rules engine. Waflz uses protocol buffers for its internal representation of ModSecurity rules. The rules can be expressed in one of three formats:
  * ModSecurity Rule Format
  * Protocol Buffers (Binary Format)
  * JSON

Simple ways of testing against the WAF:
  * Recreate false positives to identify the culprit
  * Recreate attack patterns to see how different configurations would have reacted to an attack
  * Test against the WAF to see where there may be gaps in protection In its current build, simply launching an attack will       include the alert in the response body

## Software Dependencies

1. Install dependencies. On Ubuntu 16.04 LTS, you may require the following dependencies. For easy you can create a simple        bash scipt:
   ```
   #!/bin/sh
   #Required Waflz Dependencies
   echo 'Installing Dependencies'
   echo 'Player One Ready!'

   sudo apt-get install -y git python-dev python-pip autoconf libprotobuf-dev libssl-dev libaprutil1-dev libapr1-dev uuid-dev    liblua5.1-0-dev libxml2-dev liblzma-dev libicu-dev libpcre3-dev

   #Install pip
   pip install pytest
   apt-get install -y apache2-dev protobuf-compiler
   add-apt-repository ppa:maxmind/ppa
   apt-get install -y cmake make
   apt-get update 
   apt install libmaxminddb0 libmaxminddb-dev mmdb-bin
   echo 'Great Scott!'
   exit 0
   ```
   
## Setting up Waflz Environment

1. Setup Compiler
   ```
   sudo add-apt-repository ppa:jonathonf/gcc-7.1
   ```
   ```
   sudo apt-get update
   ``` 
   ```
   sudo apt-get install gcc-7 g++-7
   ```
2. Verify default compiler is set to gcc-7:
   ```
   gcc --version
   `update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 100`
   `update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-7 50`
   ```
3. Pull down Waflz from Git:
   ```
   git clone https://github.com/VerizonDigital/waflz.git
   ```
   At the time of documentation you will need to replace the current ~/waflz-master/sub/is2 with the following clone since the    current directory is2 is empty.
   ```
   Clone into /is2 Directory
   git clone https://github.com/VerizonDigital/is2.git
   ```
4. Run the build that is located under ~/waflz-master/sub/is2
   ```
   ./build.sh
   ```
5. Additioanlly at the time of documentation you will need to Move back to the ~/waflz-master directory and comment out the      following lines within the build.sh file.
   ```
   #git submodule sync || {
   #echo "FAILED TO SYNC IS2 LIB"
   #exit 1
   #}
   #git submodule update -f --init || {
   #echo "FAILED TO UPDATE TO LATEST IS2 LIB"
   # exit 1
   #}
   ```
6. Once you have commited these changes you can now move onto running the waflz build file located in the ~/waflz-master          directory:
   ```
   ./build.sh
   ```
## Defining Rule Demo

1. For this project we will be using an example rule set from git:
   ```
   git clone https://github.com/VerizonDigital/waf.git
   sudo dpkg-deb --extract waflz_-xenial_amd64.deb ~/DIRECTORY_PATH (Create your own Directory)
   
   Move into the directory you placed the WAF rule sets:
   cd /DIRECTORY PATH/usr/bin
   
   Plug in rule example:
   ./waflz_server -r ~/WAF/Rules -f ~/WAF/Profiles/ECRS.json -g ~/WAF/GEOdb/GeoLite2-City.mmdb -s ~/WAF/GEOdb/GeoLite2-          ASN.mmdb -e waflz &
   
2. Test to ensure Waflz is running:
   ```
   curl 127.0.0.1:12345/test.sql
   ```
   ### Done!
