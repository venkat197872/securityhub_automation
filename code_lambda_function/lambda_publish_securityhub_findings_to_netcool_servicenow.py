import json
import boto3	
import os.path
import argparse
import re
from botocore.config import Config

#Lambda Handler invocation function
def get_security_hub_findings():   
    print("Getting security hub findings")
    try:
        #Process CIS controls of Master account
        print("Printing Master Account ID : ",account_id)
        get_cis_control_details_for_account(account_id)

        members_list = shclient.list_members(OnlyAssociated=True)
        #Process CIS controls of Member Accounts. When Members list is not empty process the findings for Members.

        if members_list["Members"]:
            members_list_details= members_list["Members"]
            counter = len(members_list_details)     

            #Process each Member in member list
            i=0
            while i < counter:
                member_account_id =  members_list["Members"][i]["AccountId"]
                print("Printing Member Account ID : ",member_account_id)                
                member_account_status =  members_list["Members"][i]["MemberStatus"]

                if (member_account_status=="Enabled"):
                    get_cis_control_details_for_account(member_account_id)                 
                i=i+1                       
    except Exception as e:
        print("Unable to process Findings:", e)    

#Get Findings for a given CIS Control
def get_cis_control_details_for_account(member_account_id):
    try:    
        #Get the CIS controls from AWS
        subscription_arn="arn:aws:securityhub:"+region+":"+account_id+":subscription/cis-aws-foundations-benchmark/v/1.2.0"
        #print("Subscription ARN is  : ",subscription_arn)
        response = shclient.describe_standards_controls(StandardsSubscriptionArn=subscription_arn)

        cis_controls= response["Controls"]
        counter = len(cis_controls)
        
        #For controls that are enabled get Findings from AWS
        i=0
        while i < counter:
            #print(cis_controls[i]["ControlId"],cis_controls[i]["ControlStatus"],cis_controls[i]["StandardsControlArn"])
            if (cis_controls[i]["ControlStatus"] =="ENABLED"):
                control_arn = cis_controls[i]["StandardsControlArn"]
                control_arn_new = control_arn.replace(account_id, member_account_id)
                print("Fetching findings for cis control arn : ",control_arn_new)
                findings = get_cis_control_findings(control_arn_new) 
                cis_event = {}

                #Build findings JSON to be sent to Netcool
                if findings["Findings"]:
                    cis_event["Account3LetterCode"] = account_3letter_code
                    cis_event["Provider"] = "aws"
                    cis_event["AwsAccountId"] = findings["Findings"][0]["AwsAccountId"]
                    cis_event["Region"] = region                   
                    cis_event["RuleId"] = "CIS."+findings["Findings"][0]["ProductFields"]["RuleId"]  
                    cis_event["Title"] = account_3letter_code+":"+findings["Findings"][0]["AwsAccountId"]+":"+region+":"+findings["Findings"][0]["Title"]
                    cis_event["Description"] = findings["Findings"][0]["Description"]   
                    cis_event["StandardsControlArn"] = findings["Findings"][0]["ProductFields"]["StandardsControlArn"]                                                                           
                    cis_event["ProductArn"] = findings["Findings"][0]["ProductArn"]
                    cis_event["GeneratorId"] = findings["Findings"][0]["GeneratorId"]                    
                    cis_event["RemediationUrl"] = findings["Findings"][0]["Remediation"]["Recommendation"]["Url"]                    
                    cis_event["Severity"] = "Medium" #findings["Findings"][0]["Severity"]["Label"] #Sending constant severity of Medium to Netcool/ServiceNow
                    cis_event["NumberOfFindings"] = "There are "+str(len(findings["Findings"]))+" findings in this CIS control"

                    #Publish these findings to SNS/Netcool when findings is not empty
                    #if ((findings["Findings"][0]["ProductFields"]["RuleId"])=="1.1"):                        
                    send_to_sns(json.dumps(cis_event))  

                #print(cis_event)            
                #print(i)
                #filename= "C:\\GTS\\MCMS\\code\\cis_findings\\"+member_account_id+"\\"+region+"\\"+cis_controls[i]["ControlId"]+".txt"             
                #f = open(filename, "w")
                #f.write(json.dumps(cis_event))
                #f.close()                               
            i=i+1                    

    except Exception as e:
        print("Unable to process Findings:", e)   

#Get Findings for a given CIS Control
def get_cis_control_findings(control_arn):
    try:
        #print("Control ARN is------------------",control_arn)
        response = shclient.get_findings(
            Filters=
            {
            'GeneratorId': [
                                {
                                    'Value': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark',
                                    'Comparison': 'PREFIX'
                                }
                            ],
            'ProductFields': [
                {
                    'Key': 'StandardsControlArn',
                    'Value': control_arn,
                    'Comparison': 'EQUALS'
                },
                ],        
            'ComplianceStatus': [
                    {
                        'Value': 'FAILED',
                        'Comparison': 'EQUALS'
                    }
                ],
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                },
                ],        
            }
            ) 

        return response
    except Exception as e:
        print("Unable to get findings:", e)
        return "" 

#Send Events/Findings to SNS
def send_to_sns(event): 
    #publish Event to SNS   
    print("in send_to_sns method ---------------")
    try:    
        # Publish a simple message to the specified SNS topic
        topicArn='arn:aws:sns:'+primary_region+':'+account_id+':'+sns_topic
        print("SNS topic is: ",topicArn)
        response = sns.publish(
            TopicArn=topicArn,   #TopicArn to be replaced with the Topic to publish to Netcool
            Message=event,     
        )              
    except Exception as e:
        print("Unable to publish Event to SNS Topic:", e)  

def lambda_handler(event,context):
    #Starting point of code execution
    print("Starting point of Lambda to send SecurityHub findings to Netcool.")

    #Fetch Security Hub findings per CIS control and post them to SNS topic/Netcool
    global account_3letter_code
    global account_id
    global region
    global shclient    
    global sns_topic
    global sns
    global primary_region
    try:
        # Validate account 3 letter code
        account_3letter_code = event["account_3letter_code"]   
        if not re.match(r'[A-Za-z0-9]{3}',account_3letter_code):
            raise ValueError("Account 3 letter code is not valid")

        # Configure primary region
        regions = event["enabled_regions"]
        sns_topic = event["sns_topic"] 
        session = boto3.session.Session()
        primary_region = session.region_name
        primary_config = Config(
            region_name=primary_region,
            signature_version = 'v4',
            retries = {
                'max_attempts': 10,
                'mode': 'standard'
            }
        ) 

        # Getting SecurityHub regions
        securityhub_regions = []
        if regions:
            securityhub_regions = [str(item) for item in regions.split(',')]
            print("Enabling members in these regions: {}".format(securityhub_regions))
        else:
            securityhub_regions = session.get_available_regions('securityhub')
            print("Enabling members in all available SecurityHub regions {}".format(securityhub_regions))

        #Processing each Region & enabling securityhub in that region
        for region in securityhub_regions:
                region=region.strip()
                print("Region name is:", region)
                #region = 'us-west-2'
                my_config = Config(
                    region_name=region,
                    signature_version = 'v4',
                    retries = {
                        'max_attempts': 10,
                        'mode': 'standard'
                    }
                )

                shclient = boto3.client('securityhub',config=my_config)
                sns = boto3.client('sns',config=primary_config)
                sts = boto3.client("sts",config=my_config)
                account_id = sts.get_caller_identity()["Account"]   
                
                #Get security hub findings for a region
                get_security_hub_findings()   
    except Exception as e:
        print("Unable to initialize playbook: ", e)                 
    return {
        'statusCode': 200,
        'body': json.dumps('Successfully processed SecurityHub findings')
    }