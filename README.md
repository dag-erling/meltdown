# Meltdown

This is a demonstration of the [Meltdown attack](https://meltdownattack.com/), primarily intended for FreeBSD systems.

The code should build and run on most BSD and Linux flavors, on both i386 and amd64 systems.  However, the Makefile assumes that you are building on a FreeBSD system, i386 support is only partially implemented, and functionality on non-FreeBSD systems is limited: `mdattack`'s self-test mode *should* work, and an actual attack on a carefully selected target *may* work, but `mdcheck` will not.  Patches to address these issues are more than welcome.

## Tools

### mdcheck

The `mdcheck` tool attempts to determine if your system is vulnerable.  The exact method varies from one platform to another.  The result is indicated by the exit code: 0 for complete success, 1 for partial success (mostly seen in virtual machines) and 2 for complete failure.

### mdattack

The `mdattack` tool performs a Meltdown attack on a designated target specified as a virtual address and a length and prints the result.

## Principle of operation

TBW

## Contributing

Feel free to clone this repo and submit pull requests.  Patches *must* comply with the FreeBSD [style guide](https://www.freebsd.org/cgi/man.cgi?query=style&sektion=9).

If these tools do not perform as expected on a supported and presumed-vulnerable system, and you do not have the time and / or experience to track the problem down yourself, please consider providing me with an unprivileged account on said system.

## Author and license

These tools were developed by [Dag-Erling Smørgrav](mailto:des@des.no) for the [FreeBSD project](https://www.freebsd.org/) with support from the [University of Oslo](https://www.uio.no/), and published under a [three-clause BSD license](https://opensource.org/licenses/BSD-3-Clause).  See the [LICENSE](/../..raw/master/LICENSE) file for further details.
