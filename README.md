[![Build Status](https://travis-ci.org/grdme/grd.me-server.svg)](https://travis-ci.org/grdme/grd.me-server)

Grd Me Server
=============

This is the server that handles message routing and key management for [Grd Me](https://github.com/grdme/grd.me). 

Grd Me (/ɡärd mē/) is an open source browser plugin that provides encrypted communication across any web platform.  We support aes and ecc. Available at https://grd.me.

Documentation
==============
Documentation regarding API protocols, push protocols, and testing is located [in the wiki](https://github.com/grdme/grd.me-server/wiki).

Dev Setup
==============
### 1. Install
This project uses a Vagrant virtual machine to ensure a homogeneous dev environment and simplify the installation of packages & dependancies.
To use vagrant, you must have vagrant and virtual box installed:

Install Vagrant <https://www.vagrantup.com/downloads.html>

Install Virtual Box <https://www.virtualbox.org/wiki/Downloads>

Clone this repository to your machine.
### 2. Start Vagrant
From the root directory of this repository, run:
```bash
vagrant up
```
This will create the virtual machine and install all the required packages / dependancies.

Next, run:
```bash
vagrant ssh
```
This will start an ssh session into the virtual machine.

Enter the project directory:
```bash
cd /vagrant
```
This is a synced directory with the project folder on your host machine. Any changes here will appear on your host machine and vice-versa.
### 3. Serving & Testing
To start the server, run the following commands in /vagrant on the virtual machine:
```bash
npm install
npm start
```
To run tests, run:
```bash
npm install
npm test
```
### 4. Stopping Vagrant
To stop gracefully, run the following from the project directory:
```bash
vagrant halt
```
To remove all traces of the Vagrant vm, run:
```bash
vagrant destroy
```

Cryptography Notice
======================

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software.
BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted.
See <http://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing cryptographic functions with asymmetric algorithms.
The form and manner of this distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.
