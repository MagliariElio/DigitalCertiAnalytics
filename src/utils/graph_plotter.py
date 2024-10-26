import os
import logging, warnings
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

class GraphPlotter:
    def close_all_plots(self):
        """Chiude tutte le figure aperte."""
        logging.info("Chiusura di tutte le figure aperte...")
        plt.close('all')
        return
        
    def disable_logging(self):
        logging.getLogger('matplotlib').setLevel(logging.ERROR)
        logging.getLogger('seaborn').setLevel(logging.ERROR)
        warnings.filterwarnings("ignore", category=FutureWarning)

    def plot_bar_chart(self, data, x, y, title, xlabel, ylabel, filename):
        """Crea un grafico a barre ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(14, 7))  
        
        sns.barplot(x=x, y=y, data=data, palette='viridis')
        
        plt.title(title, fontsize=16, fontweight='bold') 
        plt.xlabel(xlabel, fontsize=14)
        plt.ylabel(ylabel, fontsize=14)
        plt.xticks(rotation=45, ha='right', fontsize=12)  
        plt.yticks(fontsize=12)
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        for index, value in enumerate(data[y]):
            plt.text(index, value, f'{value}', ha='center', va='bottom', fontsize=10)

        plt.tight_layout()
        
        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)  
        
        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in {filename}.")
        plt.close()

    def plot_pie_chart(self, data, column, title, filename):
        """Crea un grafico a torta ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(8, 8))
        colors = sns.color_palette('Set2', n_colors=len(data[column]))
        
        wedges, texts, autotexts = plt.pie(data[column], labels=data.index, autopct='%1.1f%%', startangle=140, colors=colors)
        plt.title(title, fontsize=16, fontweight='bold', pad=20)
        plt.axis('equal')
        
        plt.legend(wedges, data.index, title='Legend', loc='lower right', bbox_to_anchor=(1.1, 0), fontsize=10)
        
        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)  
        
        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in {filename}.")
        plt.close()

    def plot_histogram(self, data, y, title, xlabel, ylabel, filename):
        plt.figure(figsize=(14, 8))
        
        colors = sns.color_palette("Set2")
        counts, bins, patches = plt.hist(data[y], bins=20, color=colors[0], edgecolor='black', alpha=0.7)

        plt.title(title, fontsize=16, fontweight='bold', pad=20)
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
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in {filename}.")
        plt.close()

    def plot_line_chart(self, data, x, y, title, xlabel, ylabel, filename):
        """Crea un grafico a linee ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(14, 7)) 

        sns.lineplot(x=x, y=y, data=data, marker='o', linewidth=2, markersize=6, color='blue')

        plt.title(title, fontsize=18, fontweight='bold', pad=20)  

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
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in {filename}.")
        plt.close()

    def plot_scatter_plot(self, data, x, y, title, xlabel, ylabel, filename):
        """Crea un grafico a dispersione ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(14, 8))

        sns.scatterplot(x=x, y=y, data=data, alpha=0.8, s=100, edgecolor='w')  

        plt.title(title, fontsize=18, fontweight='bold', pad=20)
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
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in {filename}.")
        plt.close()

    def plot_box_plot(self, data, x, y, title, xlabel, ylabel, filename):
        """Crea un box plot ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(12, 6))
        sns.boxplot(x=x, y=y, data=data, palette='Set2')
        plt.title(title, fontsize=16, fontweight='bold')
        plt.xlabel(xlabel, fontsize=14)
        plt.ylabel(ylabel, fontsize=14)
        plt.xticks(rotation=45, fontsize=12)
        plt.tight_layout()
        
        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)  
        
        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in {filename}.")
        plt.close()

    def plot_stacked_bar_chart(self, data, title, xlabel, ylabel, filename):
        """Crea un grafico a barre impilate ottimizzato per la visualizzazione dei dati."""
        plt.figure(figsize=(12, 6))
        colors = sns.color_palette('Set2', n_colors=len(data.columns))
        data.plot(kind='bar', stacked=True, ax=plt.gca(), color=colors)

        plt.title(title, fontsize=16, fontweight='bold')
        plt.xlabel(xlabel, fontsize=14)
        plt.ylabel(ylabel, fontsize=14)
        plt.xticks(rotation=45, ha='right', fontsize=12)
        plt.grid(axis='y', linestyle='--', alpha=0.7)  
        plt.tight_layout()
        
        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)  
        
        plt.savefig(filename, dpi=300)
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in {filename}.")
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

        plt.legend(handles=handles, title='Key Usage', bbox_to_anchor=(0.5, -0.1), loc='upper center', ncol=2, borderpad=1, labelspacing=1.2, handletextpad=1)

        plt.title(title, fontsize=20, fontweight='bold', pad=20)
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
        
        logging.info(f"Grafico '{title}' generato con successo e salvato in {filename}.")
        plt.close()

