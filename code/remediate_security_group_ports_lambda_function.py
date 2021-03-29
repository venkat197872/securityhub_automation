import json, boto3

def send_sqs_message(configuration_item_resourceId,fromport,toport,k,v,account_id):
    sqs = boto3.client('sqs')
    if k =='CidrIp':
       ip_permissions = [{'FromPort': fromport,'IpProtocol': 'tcp','IpRanges': [{'CidrIp': v}],'ToPort': toport}]
    
    if k == 'CidrIpv6':
        ip_permissions = [{'FromPort': fromport,'IpProtocol': 'tcp','Ipv6Ranges': [{'CidrIpv6': v}],'ToPort': toport}]
    
    message = "Rule: '{}' has been revoked from Security Group: '{}' in account: '{}' ".format(
                json.dumps(ip_permissions),
                configuration_item_resourceId,
                account_id
                )
    sqs_response = sqs.get_queue_url(
            QueueName='securitygroup_messsages',
            QueueOwnerAWSAccountId='628937587111')
    queue_url = sqs_response['QueueUrl']
    response = sqs.send_message(QueueUrl=queue_url,MessageBody=message)
def check_cidr_range(subnet,public_ranges,configuration_item_resourceId,fromport,toport,region,account_id):
    client = boto3.client('ec2', region_name=region)
    for k, v in subnet.items():
        if k =='CidrIp':
            if v in public_ranges:
               response = client.revoke_security_group_ingress(
               GroupId= configuration_item_resourceId,    
               IpPermissions= [
               {
               'FromPort': fromport,
               'IpProtocol': 'tcp',
               'IpRanges': [
                {
                    'CidrIp': v
                }
               ],
               'ToPort': toport
               }])
               send_sqs_message(configuration_item_resourceId,fromport,toport,k,v,account_id)
        if k =='CidrIpv6':
            if v in public_ranges:
               response = client.revoke_security_group_ingress(
               GroupId= configuration_item_resourceId,    
               IpPermissions= [
               {
               'FromPort': fromport,
               'IpProtocol': 'tcp',
               'Ipv6Ranges': [
                {
                    'CidrIpv6': v
                }
               ],
               'ToPort': toport
               }])
               send_sqs_message(configuration_item_resourceId,fromport,toport,k,v,account_id)
def check_ssh(configuration_item_resourceId,region,account_id):
    public_ranges =['0.0.0.0/0', '00.00.00.00/0', '0.0.0.0', '::/0']
    client = boto3.client('ec2', region_name=region)
    response = client.describe_security_groups(
        GroupIds = [configuration_item_resourceId])['SecurityGroups'][0]['IpPermissions']
    for i in range(len(response)):
        if 'FromPort' in response[i].keys() and 'ToPort' in response[i].keys():
            if response[i]['FromPort'] ==22 and response[i]['ToPort'] ==22:
                fromport = response[i]['FromPort']
                toport = response[i]['ToPort']
                for subnet in response[i]['IpRanges']:
                    check_cidr_range(subnet,public_ranges,configuration_item_resourceId,fromport,toport,region,account_id)
                for subnet in response[i]['Ipv6Ranges']:
                    check_cidr_range(subnet,public_ranges,configuration_item_resourceId,fromport,toport,region,account_id)
    return{
         'compliance_type': 'COMPLIANT',
         'annotation': 'The configuration is  compliant'
    }
def lambda_handler(event, context):
    print(event)
    json_string_event = json.dumps(event)
    loaded_json = json.loads(json_string_event)
    
    json_loaded_configuration_item = json.loads(loaded_json['invokingEvent'])
    # Get the Security Group ID
    try:
        configuration_item_resourceId = json_loaded_configuration_item['configurationItem']['resourceId']      
    except:
        raise KeyError(loaded_json)
        
    region =  json_loaded_configuration_item['configurationItem']['awsRegion']
    account_id = json_loaded_configuration_item['configurationItem']['awsAccountId']
    result = check_ssh(configuration_item_resourceId,region,account_id)
    config = boto3.client('config')
    response = config.put_evaluations(
        	Evaluations = [
	        {
	          'ComplianceResourceType': json_loaded_configuration_item['configurationItem']['resourceType'],
	          'ComplianceResourceId': configuration_item_resourceId,
	          'ComplianceType': result['compliance_type'],
              'Annotation': result['annotation'],
	          'OrderingTimestamp': json_loaded_configuration_item['configurationItem']['configurationItemCaptureTime']
   	        }, 
   	        ],
   	        ResultToken=event['resultToken'])