"""Explicit local recovery command. Run inside the container, then restart it."""
import os
from pathlib import Path
if __name__=='__main__':
    path=Path(os.getenv('VENGUARD_DATA','/data'))/'account.json'
    if not path.exists():print('Er is geen eigen account ingesteld. Gebruik het installatiewachtwoord uit .env.')
    elif input('Eigen account en 2FA wissen? Typ HERSTEL: ').strip()=='HERSTEL':
        path.unlink();print('Account gewist. Voer nu uit op de host: docker compose restart venguard\nLog daarna in met het installatiewachtwoord uit .env en maak een nieuw account aan. Je filters en AdGuard-servers zijn behouden.')
    else:print('Geannuleerd.')
