# Pinned Upstream CachyOS Fixtures

These fixtures are exact copies from the upstream repository:

- **Repository**: `https://github.com/CachyOS/docker-makepkg`
- **Commit SHA**: `9b0259d98e535487de07b44d7e0e7d73b7a6be29`

## Files and Blobs

| Local Fixture                                                   | Upstream Source Path             | Git Blob SHA                               |
| :-------------------------------------------------------------- | :------------------------------- | :----------------------------------------- |
| `9b0259d98e535487de07b44d7e0e7d73b7a6be29/generic.makepkg.conf` | `docker-makepkg/makepkg.conf`    | `6afec88aca2fdb4c5a813a10618286b9acc9a84f` |
| `9b0259d98e535487de07b44d7e0e7d73b7a6be29/generic.rust.conf`    | `docker-makepkg/rust.conf`       | `39305f38dc2054248662e2c8f78d19cf2988c39a` |
| `9b0259d98e535487de07b44d7e0e7d73b7a6be29/v3.makepkg.conf`      | `docker-makepkg-v3/makepkg.conf` | `2365c196385dbd9b4840eb8d298e0037f0f5b673` |
| `9b0259d98e535487de07b44d7e0e7d73b7a6be29/v3.rust.conf`         | `docker-makepkg-v3/rust.conf`    | `05294452370443e38e1fcb0a826e24a99e803667` |
| `9b0259d98e535487de07b44d7e0e7d73b7a6be29/v4.makepkg.conf`      | `docker-makepkg-v4/makepkg.conf` | `bb5263c4f4c278dcd5beb7a2d5c8bae2911d54e2` |
| `9b0259d98e535487de07b44d7e0e7d73b7a6be29/v4.rust.conf`         | `docker-makepkg-v4/rust.conf`    | `d0595a559aabc0de585614c792a3be27fa53bbea` |

These fixtures are used for deterministic, offline, unconditional build-policy
parity testing in `tests/cachyos_parity.rs`.
