"""
NetWraith – MAC Vendor Lookup Engine
====================================

Resolves MAC addresses to hardware vendor names using the mac_vendor_lookup
library. Results are cached in an LRU cache to avoid redundant lookups.
"""

import logging
from functools import lru_cache
from mac_vendor_lookup import MacLookup

logger = logging.getLogger(__name__)


class VendorLookup:
    """
    Resolves a MAC address to its hardware vendor (OUI) name.

    Uses the ``mac_vendor_lookup`` library with an in-memory LRU cache
    so repeated lookups for the same MAC are essentially free.

    Usage::

        vl = VendorLookup()
        print(vl.lookup("AA:BB:CC:DD:EE:FF"))
    """

    def __init__(self) -> None:
        """Initialise the MacLookup instance and update the local OUI table."""
        self._mac_lookup: MacLookup | None = None
        try:
            self._mac_lookup = MacLookup()
            # Attempt to update the vendor database; if offline the bundled
            # database is still usable.
            try:
                self._mac_lookup.update_vendors()
                logger.info("MAC vendor database updated successfully.")
            except Exception:
                logger.warning(
                    "Could not update MAC vendor database – using bundled data."
                )
        except Exception as exc:
            logger.error("Failed to initialise MacLookup: %s", exc)
            self._mac_lookup = None

        # Wrap the internal _do_lookup so the cache lives on the instance
        self._cached_lookup = lru_cache(maxsize=4096)(self._do_lookup)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def lookup(self, mac: str) -> str:
        """
        Return the vendor name for *mac*, or ``'Unknown'`` on failure.

        Parameters
        ----------
        mac : str
            A MAC address in any common notation
            (``AA:BB:CC:DD:EE:FF``, ``AA-BB-CC-DD-EE-FF``, etc.).

        Returns
        -------
        str
            Vendor name or ``'Unknown'``.
        """
        if not mac:
            return "Unknown"

        # Normalise to upper-case colon-separated before cache lookup
        normalised = mac.upper().replace("-", ":").replace(".", ":")
        # Handle Cisco-style aabb.ccdd.eeff → AA:BB:CC:DD:EE:FF
        if len(normalised) == 14 and normalised.count(":") == 2:
            parts = normalised.replace(":", "")
            normalised = ":".join(
                parts[i : i + 2] for i in range(0, 12, 2)
            )

        return self._cached_lookup(normalised)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _do_lookup(self, mac: str) -> str:
        """Perform the actual vendor lookup (cached externally)."""
        if self._mac_lookup is None:
            return "Unknown"
        try:
            vendor = self._mac_lookup.lookup(mac)
            return vendor if vendor else "Unknown"
        except Exception:
            return "Unknown"
