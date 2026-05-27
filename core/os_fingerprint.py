"""
NetWraith — Passive OS Fingerprinting Engine
=============================================

Guesses operating systems of network devices by examining their default
TCP packet headers (Time To Live, TCP Window Size, and Don't Fragment flag).
"""

class OSFingerprinter:
    """Helper class to analyze packet parameters for passive OS identification."""

    @staticmethod
    def fingerprint(ttl: int | None, win_size: int | None, df_flag: bool) -> str:
        """
        Estimate the Operating System of a device.

        Heuristic Baselines:
        - Windows: Default TTL = 128, Window Size = 64240 or 65535
        - Linux/Android: Default TTL = 64, Window Size = 5840 or 29200
        - macOS/iOS: Default TTL = 64, Window Size = 65535
        - Network devices: Default TTL = 255
        """
        if ttl is None:
            return "Unknown"

        # Determine base TTL by rounding up to typical defaults
        if ttl <= 64:
            base_ttl = 64
        elif ttl <= 128:
            base_ttl = 128
        else:
            base_ttl = 255

        if base_ttl == 64:
            if win_size is not None:
                if win_size in (5840, 29200, 14600):
                    return "Linux/Android"
                elif win_size == 65535:
                    return "macOS/iOS"
            return "Linux/macOS/Unix"

        elif base_ttl == 128:
            return "Windows"

        elif base_ttl == 255:
            return "Network Device"

        return "Unknown"
