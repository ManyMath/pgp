# Local Cargokit patches

`packages/pgp/cargokit/build_pod.sh`: remove the unconditional environment dump, which can expose CI secrets. Build behavior is otherwise unchanged.
