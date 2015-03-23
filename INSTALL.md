## Installing replayproxy on linux

In theory replayproxy _should_ work on windows too if you can get pynids working... but this guide assumes linux e.g. Ubuntu

### Get relayproxy code
* `git clone https://github.com/sparrowt/replayproxy.git`
* `cd replayproxy`

### Setup dependencies
* pynids library (http://jon.oberheide.org/pynids/)
* dpkt library (http://code.google.com/p/dpkt/)

Optional: setup python virtual environment to install in
* `virtualenv venv`
* `source venv/bin/activate`

#### Install **dpkt**
* `pip install dpkt`
 
#### Install **pynids**
* `wget https://jon.oberheide.org/pynids/downloads/pynids-0.6.1.tar.gz`
* `tar -xf pynids-0.6.1.tar.gz`
* `cd pynids-0.6.1`

Before building pynids you need to install its dependencies:

1. libpcap
 * `sudo apt-get install libpcap0.8 libpcap-dev`

2. libnet
 * `sudo apt-get install libnet1 libnet1-dev`

Now you can build pynids:
* `sudo apt-get install python-dev`
* `python setup.py build`

this should build `libnids` which is included in the pynids download

Then actually install pynids:
* `python setup.py install`

### Enjoy!
You should now be able to use replayproxy (see [README.md](README.md) for instructions)
