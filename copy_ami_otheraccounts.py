import boto3

target_account_id = '123XXXXXXX'
source_profile = 'aws-cli-profile'
role_on_target_account = 'arn:aws:iam::ACCOUNTID:role/ROLENAME'
source_region = 'us-east-1'
target_region = 'us-east-1'

def get_main_session():
    """
    This function returns the main session of the Master/Mgmt account.
    """
    session = boto3.Session(profile_name=source_profile, region_name=source_region)
    return session

def get_temp_cred(session, role_arn, account_id):
    """
    This function returns the temporary credentials using the trust
    relationship
    """
    get_cred_client = session.client('sts')
    get_cred_response = get_cred_client.assume_role(\
        RoleArn=role_arn,
        RoleSessionName=account_id)
    return get_cred_response['Credentials']


def get_temp_session(cred, region):
    """
    This function returns the temporary session, using the temporary
    AccessKeyId, SecretAccessKey and the SessionToken returned by the
    temporary credentials
    """
    temp_session = boto3.Session(\
        aws_access_key_id=cred['AccessKeyId'],
        aws_secret_access_key=cred['SecretAccessKey'],
        aws_session_token=cred['SessionToken'],
        region_name=region)
    return temp_session


def add_launch_permission(session, region):
    """
    This function reurns the list of filtered AMI 
    """
    ec2 = session.resource('ec2', region_name = region)
    images = ec2.images.filter(Filters=[{'Name':'name', 'Values':['Test-AMI-For-Copy*']}])
    for i in images:
        response = i.modify_attribute(
            Attribute='launchPermission',
            LaunchPermission={
                'Add': [
                    {
                        'UserId': target_account_id
                    }
                ]
            },
            OperationType='add'
        )
        print(response)
    return images

def copy_ami(session, source_region, target_region, ami_id):
    """
    This function is used to copy the unencrypted AMI to encrypted AMI using KMS key in BU account.
    """
    for i in ami_id:
        client = session.client('ec2', region_name = target_region)
        response = client.copy_image(
            Description='Encrypted Golden Image',
            Encrypted=True,
            KmsKeyId='KmsKeyId/KmsKeyARN',
            Name='Demo-Copy-AMI',
            SourceImageId=i.id,
            SourceRegion=source_region
        )
        return response["ImageId"]


def main():
    #Get Main Session
    session = get_main_session()
    #Add Launch permission for AMI
    ami_id = add_launch_permission(session , source_region)
    #Get Temp Cred
    temp_cred = get_temp_cred(session, role_on_target_account, target_account_id)
    #Get Temp Session
    temp_session = get_temp_session(temp_cred, target_region)
    #Copy AMI
    image_id = copy_ami(temp_session, source_region, target_region, ami_id)
    print(image_id)

if __name__ == '__main__':
    main()
