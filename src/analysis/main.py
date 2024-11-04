import asyncio
from analysis.certificates_analysis import certificates_analysis_main, handle_exit_signal, setup_signal_handlers

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

if __name__ == "__main__":
    # Imposta i gestori dei segnali
    setup_signal_handlers()
    
    try:
        asyncio.run(certificates_analysis_main())
    except KeyboardInterrupt:
        asyncio.run(handle_exit_signal())
