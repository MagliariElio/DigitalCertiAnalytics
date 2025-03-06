
SELECT COUNT(DISTINCT origin) FROM `chrome-ux-report.country_it.202409`;

SELECT COUNT(*) FROM `chrome-ux-report.all.202409`;

-- Query for Italian domains
SELECT DISTINCT(origin), experimental.popularity.rank 
FROM `chrome-ux-report.country_it.202409`
WHERE origin LIKE '%it%'
ORDER BY experimental.popularity.rank;

-- Query for European domains
SELECT origin, experimental.popularity.rank
FROM `chrome-ux-report.all.202409`
WHERE origin LIKE '%it%'  -- Italy
   OR origin LIKE '%fr%'  -- France
   OR origin LIKE '%de%'  -- Germany
   OR origin LIKE '%es%'  -- Spain
   OR origin LIKE '%uk%'  -- United Kingdom
   OR origin LIKE '%nl%'  -- Netherlands
   OR origin LIKE '%se%'  -- Sweden
   OR origin LIKE '%pl%'  -- Poland
   OR origin LIKE '%be%'  -- Belgium
   OR origin LIKE '%gr%'  -- Grece
   OR origin LIKE '%cz%'  -- Czech Republic
   OR origin LIKE '%pt%'  -- Portugal
   OR origin LIKE '%fi%'  -- Finland
   OR origin LIKE '%ro%'  -- Romania
   OR origin LIKE '%dk%'  -- Denmak
   OR origin LIKE '%ie%'  -- Ireland
   OR origin LIKE '%at%'  -- Austria
   OR origin LIKE '%hu%'  -- Hungary
   OR origin LIKE '%sk%'  -- Slovakia
   OR origin LIKE '%si%'  -- Slovenia
   OR origin LIKE '%hr%'  -- Croatia
   OR origin LIKE '%ee%'  -- Estonia
   OR origin LIKE '%lv%'  -- Latvia
   OR origin LIKE '%lt%'  -- Lithuania
   OR origin LIKE '%mt%'  -- Malta
   OR origin LIKE '%cy%'  -- Cipro
   OR origin LIKE '%is%'  -- Iceland
   OR origin LIKE '%no%'  -- Norway
   OR origin LIKE '%ch%'  -- Switzerland
   OR origin LIKE '%al%'  -- Albania
   OR origin LIKE '%ba%'  -- Bosnia and Herzegovina
   OR origin LIKE '%mk%'  -- North Macedonia
   OR origin LIKE '%rs%'  -- Serbia
   OR origin LIKE '%xk%'  -- Kosovo
ORDER BY experimental.popularity.rank ASC
LIMIT 10000000;

