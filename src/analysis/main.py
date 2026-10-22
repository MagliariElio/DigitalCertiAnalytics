import asyncio
import logging
import sys
from analysis.certificates_analysis import certificates_analysis_main, setup_signal_handlers, close_connections

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

if __name__ == "__main__":
    # Crea esplicitamente il loop: da Python 3.14 asyncio.get_event_loop() non ne crea più uno in automatico
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Imposta i gestori dei segnali
    # setup_signal_handlers(loop)

    interrupted = False
    try:
        loop.run_until_complete(certificates_analysis_main())
    except KeyboardInterrupt:
        interrupted = True
        logging.info("Ricevuto segnale di interruzione (SIGINT). Inizio della procedura di chiusura...")
    finally:
        try:
            # Cancella gli eventuali task rimasti in sospeso (es. dopo un KeyboardInterrupt) prima di chiudere le connessioni.
            # Un task che ha ricevuto il KeyboardInterrupt lo propaga di nuovo durante la cancellazione, quindi si riprova
            for _ in range(3):
                pending = asyncio.all_tasks(loop)
                if not pending:
                    break

                for task in pending:
                    task.cancel()

                try:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except KeyboardInterrupt:
                    interrupted = True
        finally:
            loop.run_until_complete(close_connections())
            loop.close()

    # Codice di uscita standard per un'interruzione con Ctrl+C, così eventuali comandi concatenati non proseguono
    if interrupted:
        sys.exit(130)
