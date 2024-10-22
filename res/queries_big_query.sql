
SELECT COUNT(DISTINCT origin) FROM `chrome-ux-report.country_it.202409`;

SELECT COUNT(*) FROM `chrome-ux-report.all.202409`;

-- Query per i domini italiani
SELECT DISTINCT(origin), experimental.popularity.rank 
FROM `chrome-ux-report.country_it.202409`
WHERE origin LIKE '%it%'
ORDER BY experimental.popularity.rank;

-- Query per i domini europei
SELECT origin, experimental.popularity.rank
FROM `chrome-ux-report.all.202409`
WHERE origin LIKE '%it%'  -- Italia
   OR origin LIKE '%fr%'  -- Francia
   OR origin LIKE '%de%'  -- Germania
   OR origin LIKE '%es%'  -- Spagna
   OR origin LIKE '%uk%'  -- Regno Unito
   OR origin LIKE '%nl%'  -- Paesi Bassi
   OR origin LIKE '%se%'  -- Svezia
   OR origin LIKE '%pl%'  -- Polonia
   OR origin LIKE '%be%'  -- Belgio
   OR origin LIKE '%gr%'  -- Grecia
   OR origin LIKE '%cz%'  -- Repubblica Ceca
   OR origin LIKE '%pt%'  -- Portogallo
   OR origin LIKE '%fi%'  -- Finlandia
   OR origin LIKE '%ro%'  -- Romania
   OR origin LIKE '%dk%'  -- Danimarca
   OR origin LIKE '%ie%'  -- Irlanda
   OR origin LIKE '%at%'  -- Austria
   OR origin LIKE '%hu%'  -- Ungheria
   OR origin LIKE '%sk%'  -- Slovacchia
   OR origin LIKE '%si%'  -- Slovenia
   OR origin LIKE '%hr%'  -- Croazia
   OR origin LIKE '%ee%'  -- Estonia
   OR origin LIKE '%lv%'  -- Lettonia
   OR origin LIKE '%lt%'  -- Lituania
   OR origin LIKE '%mt%'  -- Malta
   OR origin LIKE '%cy%'  -- Cipro
   OR origin LIKE '%is%'  -- Islanda
   OR origin LIKE '%no%'  -- Norvegia
   OR origin LIKE '%ch%'  -- Svizzera
   OR origin LIKE '%al%'  -- Albania
   OR origin LIKE '%ba%'  -- Bosnia ed Erzegovina
   OR origin LIKE '%mk%'  -- Macedonia del Nord
   OR origin LIKE '%rs%'  -- Serbia
   OR origin LIKE '%xk%'  -- Kosovo
ORDER BY experimental.popularity.rank ASC
LIMIT 10000000;

