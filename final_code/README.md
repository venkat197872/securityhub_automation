# aws_security_hub_automation

## How to configure, execute the program to fetch Findings and send to Netcool
```
usage: publish_securityhub_findings_to_netcool_working_16Apr_final.py --account_3letter_code AccountCode --enabled_regions ENABLED_REGIONS

required arguments:
  --account_3letter_code AccountCode
                         3 letter code of the customer account. 

optional arguments:
  --enabled_regions ENABLED_REGIONS
                        comma separated list of regions to fetch SecurityHub findings.
                        If not specified, all available regions are picked.

```
Examples:
Run below sample command command to fetch findings from specific regions like us-west-1,us-west-2 and send them to Netcool:
`publish_securityhub_findings_to_netcool_working_16Apr_final.py --account_3letter_code RRR --enabled_regions us-west-2`

Run below sample command to fetch findings from all regions:
`publish_securityhub_findings_to_netcool_working_16Apr_final.py --account_3letter_code RRR`

## Outcomes
The program will pick findings per cis control for each region, master/member accounts and post them as tickets to ServiceNow. One CIS control per region, account will be created as one ticket in ServiceNow. 


## Other Info


## Authors information (in alphabetic order)
Author information for this code.

Name | eMail
-----|------
Venkat Reddy | venkatre@in.ibm.com