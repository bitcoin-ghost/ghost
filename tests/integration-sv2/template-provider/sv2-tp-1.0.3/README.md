Stratum v2 Template Provider (c++)
=====================================

For an immediately usable, binary version of this software, see
releases.

Windows support is coming soon(tm). See https://github.com/bitcoin/bitcoin/pull/32387

The Stratum v2 spec is documented here: https://stratumprotocol.org/specification

For a general overview and how to get started, including the role of this repo,
see https://stratumprotocol.org/developers.

See also [doc/stratum-v2.md](doc/stratum-v2.md).

Compile
------------------------

```sh
cmake -B build
cmake --build build
ctest --test-dir build
```

See `doc/build*` for detailed instructions per platform, including
dependencies.

Usage
------------------------
Download or compile Bitcoin Core v30.0 or later. Start it with:

 ```sh
 bitcoin -m node -ipcbind=unix
 ```

Then start the Template Provider, thorough logging is recommended:

```sh
build/bin/sv2-tp -debug=sv2 -loglevel=sv2:trace
```

(for the installed version you don't need `build/bin/`)

Now connect on of the other Stratum v2 roles to the Template Provider, such
as the Job Declarator Client or (e.g. for solo mining) the Pool role. You'll
need to provide the [Auhority Key]() which `sv2-tp` prints in the log.

See https://github.com/stratum-mining/stratum.

Configuration
------------------------
`sv2-tp` reads its own configuration file. By default it looks for
`sv2-tp.conf` inside the data directory (for example
`~/.bitcoin/sv2-tp.conf`). This keeps Template Provider settings separate from
the Bitcoin Core node configuration in `bitcoin.conf` and prevents warnings
about unrelated options. You can override the location with `-conf=<path>` or
set `-conf=0` to disable config file loading entirely.

Here is an example configuration:

```ini
chain=signet

ipcconnect=unix
sv2interval=30
sv2feedelta=1000

# Logging
debug=sv2
loglevel=sv2:trace
debug=ipc
```

Troubleshooting
------------------------

All submitted blocks are stored in the data directory. To inspect in hex format:

```sh
xxd -p ~/.bitcoin/$BLOCK_HASH.dat | tr -d '\n'; echo
```


Relation to Bitcoin Core
------------------------

The code for this project is originally based on Bitcoin Core, for historical
reasons described [here](https://github.com/bitcoin/bitcoin/pull/31802). The
code is expected to diverge over time, with unused code being removed.

There is no test coverage for code that is identical to the upstream project
and bugs there should be fixed upstream, with a pull request here if they're
important.

There's still many places where text will simply refer to "Bitcoin Core". Only
replace this text if the rest of the file differs from upstream.

Where's the main code?
----------------------

- `src/sv2`: Stratum v2 noise protocol, transport, network and template provider
- `test/sv2*`: test coverage

The rest is original Bitcoin Core code, albeit stripped down. E.g. the functional
testwork has been removed, as has the wallet, GUI, RPC, ZMQ and most p2p code.

Pull requests to strip out additional unused code are welcome. The main barrier
to that is that `sv2_template_provider_tests` requires real node functionality.
This should be replaced with a mock, after which the `libbitcoin_node` target
can be dropped and many other things.
