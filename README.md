这是一个长期开发的项目。我希望创建一个内部使用的CVE信息系统，每天定时从https://nvd.inst.org/拉取公司信息资产的漏洞情报并生成报告。
本项目分成3部分
第1，创建资产列表inventory.csv。这个文件包含厂家，系统版本及cpe。
第2.1，利用python脚本，根据invenroty.csv中的cpe项目向https://services.nvd.nist.gov/rest/json/cves/2.0发送api-call，从而获取cve信息。
第2.2，对cve信息进行过滤，发布日期或修改日期为1日内(为了让sample的report呈现更多结果，在脚本中设置为7日)，且baseseverity为Medium或以上(Medium,High,Critcal)的信息保存到以invenroty.csv文件中的os_version元素命名的json文件
第2.3，提取结果中信息，把json文件中的cve_id，vendor，os_version，description，published，lastModified，basescore，baseseverity，refer_url，versionStartIncluding，versionEndExcluding的内容提取，并且对cve_id进行去重处理，合并vendor及os_version的内容，生成report.cvs文件
第3，开发中……考虑利用docker nginx创建一个简单的网页，把inventory信息和cve port呈现出来。后续可以通过网页对inventory信息进行增加，删除，修改。

目前发现的问题和需要优化的方面：
1. 目前inventory.csv的cpe信息是查询了official-cpe-dictionary_v2.3.xml后人手录入，未能实现批量化和自动化(例如针对cisco nx-os 8.0以上的版本获取cpe)，以后要考虑可以实现批量增加cpe
2. 目前脚本执行时间比较长，需要优化脚本进行提速。
3. 欢迎各位提出优化建议。

===========================================================================================================================================================
This is a long-term development project. I aim to create an internal CVE information system that pulls vulnerability intelligence related to the company's assets information from https://nvd.inst.org/ daily on a scheduled basis and generates reports.

The project consists of three parts:
1. Create an asset list (inventory.csv).
This file contains fields for vendor, system version, and CPE.

2.1. Use a Python script to send API calls to https://services.nvd.nist.gov/rest/json/cves/2.0
The API requests are based on the CPE entries in inventory.csv to fetch CVE information.

2.2. Filter the CVE data.
Extract CVE information where the published or modified date is within 1 day (set to 7 days in the script for a larger sample of results in the report) and where the base severity is Medium or higher (Medium, High, Critical). Save the filtered data to JSON files named according to the os_version field in inventory.csv.

2.3. Extract and de-duplicate results.
From the JSON files, extract the following information: cve_id, vendor, os_version, description, published, lastModified, basescore, baseseverity, refer_url, versionStartIncluding, and versionEndExcluding. De-duplicate cve_id entries, consolidate vendor and os_version fields, and generate a report.csv file.

3. Further development (in progress):
Consider using Docker and Nginx to create a simple web interface. This interface would display inventory information and CVE reports. Future functionalities could include adding, deleting, and modifying inventory entries via the web interface.

Current Issues and Areas for Optimization:
CPE data input:
Currently, the CPE information in inventory.csv is manually entered after referencing official-cpe-dictionary_v2.3.xml. This process lacks batch processing and automation (e.g., obtaining CPEs for Cisco NX-OS versions 8.0 and above). A batch addition mechanism for CPEs should be considered in the future.

Script performance:
The script execution time is relatively long and needs optimization for better performance.

Suggestions welcome:
Contributions and suggestions for optimization are highly encouraged.
