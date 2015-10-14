PCAPparse
=========

The program parses the given pcap file trying to extract the ntlm challenge response
 or ftp user and password. (Was written to crack FRA challenge 2015, part 4)

## Dependencies
Pcap parse requires [gopacket](https://github.com/google/gopacket).
To compile gopacket header files from pcaplib need to be installed.

## Installation

```bash
$ go get -u github.com/chrjoh/pcapparse
```

## Usage

```bash
$ pcapparse --help

Command line arguments:

  -i "steg3.pcap": Input file (.pcap)
  -o "output_steg3.lc": Output file (.lc)
  -t "ntlm" select what type to look for in the pcap file: ntlm or ftp
```

## License (MIT)

Copyright (c) 2015 [Christer Johansson](http://blog.lodakai.com/)

> Permission is hereby granted, free of charge, to any person obtaining
> a copy of this software and associated documentation files (the
> "Software"), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject to
> the following conditions:

> The above copyright notice and this permission notice shall be
> included in all copies or substantial portions of the Software.

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
> EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
> MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
> NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
> LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
> OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
> WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
