# as_reserved_slots (Plugify)

Keeps a number of server slots ('public_slots' in reserved_slots.ini) free for players carrying the reserve permission/flag: a non-reserve player authorizing while the server holds more than public_slots non-reserve players is disconnected, and a reserve player takes the slot of the first non-reserve player. Ported from the Pisex admin_system module 'Reserved_slots' ([AS] Reserved slots by ABKAM), keeping the config keys, the permission/flag check and the kick reason. Requires the admin_system core.

Plugify port (fork) of **Reserved_slots ([AS] Reserved slots)** by ABKAM (Metamod (C++)).
Original: https://github.com/Pisex/cs2-admin_system_modules
The code was rewritten for Plugify / s2sdk; behaviour follows the original.

## Requirements
- [Plugify](https://github.com/untrustedmodders/plugify) with [s2sdk](https://github.com/untrustedmodders/plugify-plugin-s2sdk)
- Plugify dependencies: s2sdk, admin_system, hudmenu (optional)

## Installation
Download `as_reserved_slots-1.0.1.zip` from Releases and extract it into `game/csgo/`.

## Building
Requires Docker. `./build.sh` builds in the Steam Runtime 3 (sniper) SDK image; the package
is written to `build/package/as_reserved_slots`.

`plugins/admin_system` carry only the API headers of the plugins this one uses.

## License
GPL-3.0, see LICENSE.

