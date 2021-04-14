import json
import boto3	
import os.path
import argparse
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
        print("Subscription ARN is  : ",subscription_arn)
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
                #print(i)
                #filename= "C:\\GTS\\MCMS\\code\\cis_findings\\"+member_account_id+"\\"+cis_controls[i]["ControlId"]+".txt"             
                #f = open(filename, "w")
                #f.write(json.dumps(findings))
                #f.close() 

                #Publish these findings to SNS/Netcool when findings is not empty
                #if findings["Findings"]:
                    #send_to_sns(json.dumps(findings))                              
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
        response = sns.publish(
            TopicArn='arn:aws:sns:us-west-2:802878444238:test_topic',   #TopicArn to be replaced with the Topic to publish to Netcool
            Message=event,     
        )            
        #message_id = response['MessageId']     
    except Exception as e:
        print("Unable to publish Event to SNS Topic:", e)  

#Starting point of code execution
#Fetch Security Hub findings per CIS control and post them to SNS topic/Netcool
print("hello world2")

parser = argparse.ArgumentParser(description='Link AWS Accounts to central SecurityHub Account')
parser.add_argument('--enabled_regions', type=str, help="comma separated list of regions to enable SecurityHub. If not specified, all available regions enabled")
args = parser.parse_args()

# Getting SecurityHub regions
session = boto3.session.Session()

securityhub_regions = []
if args.enabled_regions:
    securityhub_regions = [str(item) for item in args.enabled_regions.split(',')]
    print("Enabling members in these regions: {}".format(securityhub_regions))
else:
    securityhub_regions = session.get_available_regions('securityhub')
    print("Enabling members in all available SecurityHub regions {}".format(securityhub_regions))

#Processing each Region & enabling securityhub in that region
for region in securityhub_regions:
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
        sns = boto3.client('sns',config=my_config)
        sts = boto3.client("sts",config=my_config)
        account_id = sts.get_caller_identity()["Account"]   
        
        #Get security hub findings for a region
        get_security_hub_findings()         