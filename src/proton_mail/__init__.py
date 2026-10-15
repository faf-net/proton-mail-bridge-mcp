"""Read-only Proton Mail connector via Proton Bridge (IMAP).

Gemeinsamer Kern für zwei Frontends:
- MCP-Server (read-only, on-demand Zugriff für Claude)
- Export-Lauf (alle Mails + Anhänge auf die NAS schreiben)

Bewusst KEIN Schreib-/Sende-/Löschpfad im Lese-Kern.
"""

__version__ = "0.1.0"
