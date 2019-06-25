# FMC-API
Simple Scripts to Add and Remove Objects via the FMC API


Both Scripts will first request a file with device info, then will request information for connecting to the FMC API (IP, Domain UUID, Username, and Password).

Domain UUID can be found at https://[FMC IP]/api/api-explorer then selecting one of the API methods and selecting "Try it out".

The csv file for FMC_Add_Objects.py should be in the format Name,Value,Type,Description

Supported types are Host, Network, Range, and FQDN

*See MultiTest.csv for an example

The csv file for FMC_Del_Objects.py should be in the format Id,Type

Supported types are Host, Network, Range, and FQDN

*See MultiTestDel.csv for an example
