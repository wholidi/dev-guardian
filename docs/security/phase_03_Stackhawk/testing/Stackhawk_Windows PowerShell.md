Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\930140> hawk version
v5.5.0
PS C:\Users\930140> hawk init
Please enter your StackHawk API key.
To create a new API key, visit https://app.stackhawk.com/settings/apikeys: hawk.JelSed453XNJ9tlY1Jlu.OiMp1ZndQtPkU0tOBNi5
Authenticated!
PS C:\Users\930140> hawk scan hawk://ec_e21f3df7-c313-40d8-a3c4-2bccfdbe2d8b
StackHawk ≡ƒªà HAWKSCAN - v5.5.0
* application:             Dev-Guardian
* environment:             Development
* scan id:                 9ef8260f-fb35-4d91-8b4a-5df0bdbe496f
* scan configs:            ['hawk://ec_e21f3df7-c313-40d8-a3c4-2bccfdbe2d8b']
* app host:                https://dev-guardian-production.up.railway.app/
* hawk memory:             5g
* scan policy:             DEFAULT (HawkScan Default)
View on StackHawk platform: https://app.stackhawk.com/scans/9ef8260f-fb35-4d91-8b4a-5df0bdbe496f
Default Context Spider complete
Discovered 2 URLs:
https://dev-guardian-production.up.railway.app/robots.txt
  https://dev-guardian-production.up.railway.app/sitemap.xml
Default Context Passive scanning complete
Default Context Active scan of https://dev-guardian-production.up.railway.app complete
Default Context Passive scanning complete
Scan results for https://dev-guardian-production.up.railway.app/
------------------------------------------------------------
Criticality: New/Triaged
   High: 0/0    Medium: 0/0    Low: 3/0
------------------------------------------------------------
1) Strict-Transport-Security Header Not Set
   Risk: Low
   Cheatsheet:
   Paths (3):
     [New] GET
     [New] GET /robots.txt
     [New] GET /sitemap.xml
View on StackHawk platform: https://app.stackhawk.com/scans/9ef8260f-fb35-4d91-8b4a-5df0bdbe496f
PS C:\Users\930140> hawk scan hawk://ec_e21f3df7-c313-40d8-a3c4-2bccfdbe2d8b
StackHawk ≡ƒªà HAWKSCAN - v5.5.0
* application:             Dev-Guardian
* environment:             Development
* scan id:                 df2a1d08-20f9-4d63-93e7-fac00ed9df16
* scan configs:            ['hawk://ec_e21f3df7-c313-40d8-a3c4-2bccfdbe2d8b']
* app host:                https://dev-guardian-production.up.railway.app/
* hawk memory:             5g
* scan policy:             DEFAULT_API (OpenAPI/REST API)
* OpenAPI:                 https://dev-guardian-production.up.railway.app/openapi.json
View on StackHawk platform: https://app.stackhawk.com/scans/df2a1d08-20f9-4d63-93e7-fac00ed9df16
Default Context Custom Spider complete
Default Context Spider complete
Discovered 11 URLs:
https://dev-guardian-production.up.railway.app/analyze-file
  https://dev-guardian-production.up.railway.app/analyze-zip-html
  https://dev-guardian-production.up.railway.app/health
  https://dev-guardian-production.up.railway.app/lc-supervisor-zip
  https://dev-guardian-production.up.railway.app/multi-agent-file
  https://dev-guardian-production.up.railway.app/multi-agent-file-json
  https://dev-guardian-production.up.railway.app/robots.txt
  https://dev-guardian-production.up.railway.app/scan
  https://dev-guardian-production.up.railway.app/sitemap.xml
  https://dev-guardian-production.up.railway.app/supervisor-zip
  ... 1 additional URLs
Default Context Passive scanning complete
Default Context Active scan of https://dev-guardian-production.up.railway.app complete
Scan results for https://dev-guardian-production.up.railway.app/
------------------------------------------------------------
Criticality: New/Triaged
   High: 0/0    Medium: 4/0    Low: 21/0
------------------------------------------------------------
1) Anti-CSRF Tokens Check
   Risk: Medium
   Cheatsheet: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md
   Paths (2):
     [New] GET /ui
     [New] GET /ui
2) Content Security Policy (CSP) Header Not Set
   Risk: Medium
   Cheatsheet:
   Paths (1):
     [New] GET /ui
3) Missing Anti-clickjacking Header
   Risk: Medium
   Cheatsheet:
   Paths (1):
     [New] GET /ui
4) X-Content-Type-Options Header Missing
   Risk: Low
   Cheatsheet:
   Paths (2):
     [New] GET /health
     [New] GET /ui
5) Strict-Transport-Security Header Not Set
   Risk: Low
   Cheatsheet:
   Paths (19):
     [New] GET /health
     [New] POST /analyze-zip-html
     [New] POST /supervisor-zip
     [New] POST /lc-supervisor-zip
     [New] POST /scan
     ... 14 more in details
View on StackHawk platform: https://app.stackhawk.com/scans/df2a1d08-20f9-4d63-93e7-fac00ed9df16