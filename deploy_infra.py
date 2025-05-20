import boto3
import json

# AWS-Clients initialisieren
iam_client = boto3.client('iam')
lambda_client = boto3.client('lambda')
s3_client = boto3.client('s3')

# Variablen definieren
lambda_function_name = "PositionDataValidator"
bucket_name = "PositionDataStorage"
role_name = "LambdaS3ExecutionRole"

account_id = input("Bitte gib deine Account ID an: ")

# Lambda Code Laden
with open('lambda_code.zip', 'rb') as f:
    lambda_code_zip = f.read()

#S3-Bucket erstellen
try:
    s3_client.create_bucket(Bucket=bucket_name)
    print(f"S3-Bucket '{bucket_name}' created.")
except s3_client.exceptions.BucketAlreadyExists:
    print(f"S3-Bucket '{bucket_name}' already exists.")
except Exception as e:
    print(f"Error creating S3 bucket: {e}")

# IAM-Rolle für die Lambda erstellen
try:
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    role_response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy),
        Description='Role for Lambda function to access S3'
    )
    print("IAM Role created:", role_response['Role']['Arn'])

    # Berechtigungen zur Rolle hinzufügen
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject"
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }
        ]
    }

    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='S3AccessPolicy',
        PolicyDocument=json.dumps(s3_policy)
    )

except iam_client.exceptions.EntityAlreadyExistsException:
    print("IAM Role already exists.")

# Lambda-Funktion erstellen
try: 
    response = lambda_client.create_function(
        FunctionName=lambda_function_name,
        Runtime='python3.13',  # oder die gewünschte Python-Version
        Role=f'arn:aws:iam::{account_id}:role/{role_name}',
        Handler='lambda_function.lambda_handler',
        Code={
            'ZipFile': lambda_code_zip
        },
        Description='Lambda function to validate position data and store in S3',
        Timeout=30,
        MemorySize=128,
    )
    print("Lambda function created:", response)
except lambda_client.exceptions.ResourceConflictException:
    print("Lambda function already exists. Trying to Update...")
    try: 
        response = lambda_client.update_function_code(
            FunctionName=lambda_function_name,
            ZipFile=lambda_code_zip
        )
        print("Success!")
    except Exception as e:
        print(f"Error updating Lambda bucket: {e}")
