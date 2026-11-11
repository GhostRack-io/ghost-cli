# Backup format

The encrypted container of a GhostRack backup (`GHBKP001` and `GHBKP002`), as
read by the restore on a host and by `ghost backup decrypt`: the records, the
manifest and the footer, their authentication, and the unwrapping of the
backup's data key. Both read it with this crate, so a backup one can read the
other can. The crate is licensed under Apache-2.0; see [LICENSE](LICENSE).
