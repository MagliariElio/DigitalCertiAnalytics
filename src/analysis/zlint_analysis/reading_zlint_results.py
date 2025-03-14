import csv
from pymongo import MongoClient
from collections import defaultdict, Counter

client = MongoClient('mongodb://localhost:27017/')
db = client['Leaf_Zlint_Checks']
collection = db['zlint_results']

# --- Part 1: Ranking for each field by result ---
results_data = defaultdict(lambda: defaultdict(lambda: {'total': 0, 'issuers': Counter()}))

for doc in collection.find():
    # issuer = doc.get("issuer_organization")
    issuer = doc.get("issuer_dn")
    zlint_results = doc.get("zlint_results", {})
    for field, detail in zlint_results.items():
        res_val = detail.get("result")
        results_data[res_val][field]['total'] += 1
        results_data[res_val][field]['issuers'][issuer] += 1

with open("zlint_results.csv", mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow(["result", "field", "total", "top_issuer", "top_count"])

    for res_val, fields in results_data.items():
        ranking = []
        for field, data in fields.items():
            total = data['total']
            top_issuer, top_count = data['issuers'].most_common(1)[0]
            ranking.append((field, total, top_issuer, top_count))

        ranking.sort(key=lambda x: x[1], reverse=True)

        for field, total, top_issuer, top_count in ranking:
            writer.writerow([res_val, field, total, top_issuer, top_count])

print("The results by field have been written in 'zlint_results.csv'.")

# --- Part 2: Aggregated ranking of issuers by result ---
aggregated_issuers = defaultdict(Counter)

for doc in collection.find():
    issuer = doc.get("issuer_dn")
    zlint_results = doc.get("zlint_results", {})
    for field, detail in zlint_results.items():
        res_val = detail.get("result")
        aggregated_issuers[res_val][issuer] += 1

with open("issuer_ranking_by_result.csv", mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow(["result", "issuer", "count", "rank"])

    for res_val, issuer_counter in aggregated_issuers.items():
        ranking = sorted(issuer_counter.items(), key=lambda x: x[1], reverse=True)
        rank = 1
        for issuer, count in ranking:
            writer.writerow([res_val, issuer, count, rank])
            rank += 1

print("The issuer ranking by type has been written in 'issuer_ranking_by_result.csv'")

# --- Part 3: Count certificates with at least one occurrence of each result ---
certificate_result_counts = Counter()

for doc in collection.find():
    zlint_results = doc.get("zlint_results", {})
    unique_results = {detail.get("result") for detail in zlint_results.values()}
    for res in unique_results:
        certificate_result_counts[res] += 1

with open("certificates_result_summary.csv", mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow(["result", "certificate_count"])
    for res, count in sorted(certificate_result_counts.items(), key=lambda x: x[1], reverse=True):
        writer.writerow([res, count])

print("The certificate summary has been written in 'certificates_result_summary.csv'.")

client.close()