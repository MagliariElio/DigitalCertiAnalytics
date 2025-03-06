import os
import logging, warnings
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

class GraphPlotter:
    def close_all_plots(self):
        """Chiude tutte le figure aperte."""
        logging.info("Chiusura di tutti i grafici aperti...")
        plt.close('all')
        return
        
    def disable_logging(self, is_verbose:bool):
        """Disabilita il logging dettagliato per alcune librerie se la modalità verbose è disattivata."""
        logging.getLogger('PIL.PngImagePlugin').setLevel(logging.ERROR)
        logging.getLogger('matplotlib').setLevel(logging.ERROR)
        warnings.filterwarnings("ignore", category=FutureWarning)
        if(not is_verbose):
            logging.getLogger('seaborn').setLevel(logging.ERROR)
        return

    def plot_bar_chart(self, data, x, y, title, xlabel, ylabel, filename, text_offset=3):
        """Crea un grafico a barre ottimizzato per la visualizzazione dei dati."""

        sns.set_style("whitegrid")
        plt.rcParams.update({
            'font.family': 'serif',
            'font.size': 12,
            'axes.titlesize': 16,
            'axes.titleweight': 'bold'
        })

        fig, ax = plt.subplots(figsize=(14, 7), dpi=300)

        sns.barplot(x=x, y=y, data=data, palette='viridis', ax=ax)

        # ax.set_title(title, fontsize=16, fontweight='bold', pad=30)
        ax.set_xlabel(xlabel, fontsize=14)
        ax.set_ylabel(ylabel, fontsize=14)

        plt.xticks(rotation=45, ha='right', fontsize=12)
        plt.yticks(fontsize=12)

        ax.grid(axis='y', linestyle='--', alpha=0.7)

        for patch in ax.patches:
            height = patch.get_height()
            # Se il valore è un numero intero, lo formatta senza decimali
            value_text = f'{height:.0f}'
            # Calcola la posizione orizzontale (al centro della barra)
            x_position = patch.get_x() + patch.get_width() / 2.0
            # Posiziona il testo con un offset verticale definito da text_offset
            ax.text(x_position, height + text_offset, value_text,
                    ha='center', va='bottom', fontsize=10)

        plt.tight_layout()

        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

        plt.savefig(filename, dpi=300, bbox_inches='tight')
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
        plt.close()
    
    def plot_pie_chart(self, data, column, title, filename, legend_loc='best', 
                   legend_fontsize=10, autopct_fontsize=10):
        """Crea un grafico a torta ottimizzato per la visualizzazione dei dati."""
        
        sns.set_style("whitegrid")
        plt.rcParams.update({
            'font.family': 'serif',
            'font.size': 12,
            'axes.titlesize': 16,
            'axes.titleweight': 'bold'
        })
        
        fig, ax = plt.subplots(figsize=(9, 9), dpi=300)
        colors = sns.color_palette('muted', n_colors=len(data))
        
        def autopct_format(pct):
            return f'{pct:.1f}%' if pct > 0.1 else ''
        
        explode = [0.06] * len(data)
        
        wedges, _, autotexts = ax.pie(
            data[column],
            autopct=autopct_format,
            startangle=140,
            colors=colors,
            wedgeprops={'edgecolor': 'white', 'linewidth': 1.5},
            pctdistance=1.05,
            explode=explode
        )
        
        for autotext in autotexts:
            autotext.set_fontsize(autopct_fontsize)
            autotext.set_fontweight('medium')
            autotext.set_color('black')
        
        # ax.set_title(title, pad=20)
        ax.axis('equal')
        
        legend = ax.legend(
            wedges,
            data.index,
            title="Legend",
            loc=legend_loc,
            bbox_to_anchor=(1.1, 1),
            fontsize=legend_fontsize,
            frameon=True,
            framealpha=0.9,
            borderpad=1
        )
        plt.setp(legend.get_title(), fontsize=legend_fontsize, fontweight='bold')
        
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
        plt.close()

    def plot_histogram(self, data, y, title, xlabel, ylabel, filename):
        plt.figure(figsize=(14, 8))
        
        colors = sns.color_palette("Set2")
        counts, bins, patches = plt.hist(data[y], bins=20, color=colors[0], edgecolor='black', alpha=0.7)

        # plt.title(title, fontsize=16, fontweight='bold', pad=20)
        plt.xlabel(xlabel, fontsize=14)
        plt.ylabel(ylabel, fontsize=14)
        plt.xticks(fontsize=12)
        plt.yticks(fontsize=12)
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        bin_centers = 0.5 * (bins[1:] + bins[:-1])
        for count, x in zip(counts, bin_centers):
            plt.text(x, count, f'{int(count)}', ha='center', va='bottom', fontsize=10)
        
        plt.tight_layout()
        plt.subplots_adjust(top=0.9)

        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)

        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
        plt.close()

    def plot_line_chart(self, data, x, y, title, xlabel, ylabel, filename):
        """Crea un grafico a linee ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(14, 7)) 

        sns.lineplot(x=x, y=y, data=data, marker='o', linewidth=2, markersize=6, color='blue')

        # plt.title(title, fontsize=18, fontweight='bold', pad=20)  

        plt.xlabel(xlabel, fontsize=16, labelpad=10)
        plt.ylabel(ylabel, fontsize=16, labelpad=10)

        plt.xticks(rotation=45, ha='right', fontsize=12)
        plt.yticks(fontsize=12)

        plt.grid(True, linestyle='--', alpha=0.7)

        plt.tight_layout()

        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)

        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
        plt.close()

    def plot_scatter_plot(self, data, x, y, title, xlabel, ylabel, filename):
        """Crea un grafico a dispersione ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(14, 8))

        sns.scatterplot(x=x, y=y, data=data, alpha=0.8, s=100, edgecolor='w')  

        # plt.title(title, fontsize=18, fontweight='bold', pad=20)
        plt.xlabel(xlabel, fontsize=16)
        plt.ylabel(ylabel, fontsize=16)
        plt.xticks(fontsize=14)
        plt.yticks(fontsize=14)

        plt.grid(True, linestyle='--', alpha=0.6)

        plt.tight_layout()
        plt.subplots_adjust(top=0.9)

        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)  

        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
        plt.close()

    def plot_box_plot(self, data, x, y, title, xlabel, ylabel, filename):
        """Crea un box plot ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(12, 6))
        sns.boxplot(x=x, y=y, data=data, palette='Set2')
        # plt.title(title, fontsize=16, fontweight='bold')
        plt.xlabel(xlabel, fontsize=14)
        plt.ylabel(ylabel, fontsize=14)
        plt.xticks(rotation=45, fontsize=12)
        plt.tight_layout()
        
        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)  
        
        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
        plt.close()

    def plot_stacked_bar_chart(self, data, title, xlabel, ylabel, filename):
        """Crea un grafico a barre impilate ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(12, 6))
        colors = sns.color_palette('Set2', n_colors=len(data.columns))
        data.plot(kind='bar', stacked=True, ax=plt.gca(), color=colors)

        # plt.title(title, fontsize=16, fontweight='bold')
        plt.xlabel(xlabel, fontsize=14)
        plt.ylabel(ylabel, fontsize=14)
        plt.xticks(rotation=45, ha='right', fontsize=12)
        plt.grid(axis='y', linestyle='--', alpha=0.7)  
        plt.tight_layout()
        
        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)  
        
        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
        plt.close()

    def plot_dot_plot(self, data, x, y, title, xlabel, ylabel, filename):
        """Crea un dot plot ottimizzato per la visualizzazione dei dati con legenda."""
        plt.figure(figsize=(20, 14))  

        unique_key_usages = data.index.unique()

        palette = sns.color_palette('viridis', n_colors=len(unique_key_usages))
        color_mapping = dict(zip(unique_key_usages, palette))

        data['Color'] = data.index.map(color_mapping)
        sns.stripplot(x=x, y=data.index, data=data, size=15, palette=color_mapping, alpha=0.7, jitter=True)

        handles = [plt.Line2D([0], [0], marker='o', color='w', label=f'{i+1}: {key_usage}',
                            markersize=10, markerfacecolor=color_mapping[key_usage])
                for i, key_usage in enumerate(unique_key_usages)]

        plt.legend(handles=handles, title='Legend', bbox_to_anchor=(-0.5, -0.1), loc='upper center', ncol=3, borderpad=1, labelspacing=1.2, handletextpad=1)

        # plt.title(title, fontsize=20, fontweight='bold', pad=20)
        plt.xlabel(xlabel, fontsize=16)

        plt.yticks(ticks=range(len(unique_key_usages)), labels=range(1, len(unique_key_usages) + 1), fontsize=14)

        plt.ylabel(ylabel, fontsize=16)
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        plt.tight_layout()
        plt.subplots_adjust(bottom=0.25)

        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)

        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
        plt.close()

    def plot_horizontal_bar(self, data, x, y, title, xlabel, ylabel, filename):
        """Crea un grafico a barre orizzontali per la visualizzazione dei dati con legenda."""

        sns.set_style("whitegrid")
        plt.rcParams.update({
            'font.family': 'serif',
            'font.size': 12,
            'axes.titlesize': 20,
            'axes.titleweight': 'bold'
        })

        fig, ax = plt.subplots(figsize=(20, 14), dpi=300)

        unique_categories = data.index.unique()

        palette = sns.color_palette('viridis', n_colors=len(unique_categories))
        color_mapping = dict(zip(unique_categories, palette))

        data['Color'] = data.index.map(color_mapping)

        sns.barplot(x=x, y=y, data=data, hue=data.index, dodge=False,
                    palette=color_mapping, ci=None, ax=ax)

        # ax.set_title(title, pad=20)
        ax.set_xlabel(xlabel, fontsize=16)
        ax.set_ylabel(ylabel, fontsize=16)

        ax.tick_params(axis='x', labelsize=14)
        ax.tick_params(axis='y', labelsize=14)

        ax.grid(axis='x', linestyle='--', alpha=0.7)

        for patch in ax.patches:
            width = patch.get_width()
            height = patch.get_height()
            ax.text(width + 0.01 * width, patch.get_y() + height/2,
                    f'{width:.0f}', ha='left', va='center', fontsize=12)

        plt.tight_layout()
        
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

        plt.savefig(filename, dpi=300, bbox_inches='tight')
        logging.info(f"Grafico '{title}' generato con successo e salvato in file://{filename}.")
        plt.close()
        
    