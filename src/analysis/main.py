import asyncio
from analysis.certificates_analysis import certificates_analysis_main, setup_signal_handlers, close_connections

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

if __name__ == "__main__":
    # Imposta i gestori dei segnali
    loop = asyncio.get_event_loop()
    setup_signal_handlers(loop)
    loop.run_until_complete(certificates_analysis_main())
    loop.run_until_complete(close_connections())
    loop.close()
