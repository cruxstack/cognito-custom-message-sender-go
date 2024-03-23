# Cognito Custom Message Sender

This AWS Lambda-based solution enables dynamic, policy-driven email responses to
AWS Cognito events, utilizing AWS Simple Email Service (SES) for delivery.
Tailor email content and sending behavior dynamically with Open Policy Agent
(OPA) policies, providing a flexible and powerful tool for managing user
communications in response to specific triggers within AWS Cognito. Ideal for
applications requiring customized user engagement or notification strategies.

## Features

- **AWS Lambda Integration**: Handle Cognito Custom Email Sender events, sending
  emails according to OPA policies.
- **Policy-based Email Sending**: Use OPA for fine-grained control over email
  content and sending behavior.

## Lambda Function

Trigger the Lambda function by configuring Cognito to send Custom Email Sender
events. Ensure your Lambda function is set as the destination for these events.

### Build

#### Prerequisites

- AWS account with access to SES, Lambda, and KMS.
- Configured AWS CLI with appropriate permissions.
- Go 1.22.1+ installed for building the project.
- Knowledge of Open Policy Agent for defining policies.

#### Steps

1. Clone the repository:

    ```bash
    git clone https://github.com/cruxstack/cognito-custom-message-sender-go.git
    cd cognito-custom-message-sender-go
    ```

2. Build the project for Linux as `bootstrap` binary:

    ```bash
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap
    ```

3. Add OPA Policy:

    ```rego
    package cognito_custom_sender_email_policy
    result := {
        "action": "allow",
        "allow": {
            "templateID": "REPLACE_WITH_SES_TEMPLATE_NAME",
            "templateData": {},
            "srcAddress": "noreply@example.com",
            "dstAddress": input.userAttributes.email,
        },
    }
    ```

4. Create a ZIP archive:

    ```bash
    zip deployment.zip main policy.rego

    ```

### Create Lambda Function

#### Steps

- Create a KMS key in the AWS Management Console
    - Required as AWS uses it to encrypt the verification code.
- Create a IAM Role with the following permissions:
    - `AWSLambdaBasicExecutionRole` Managed Policy
    - `kms:Decrypt` for the KMS key
    - `ses:GetTemplate` for fetching SES templates
    - `ses:SendTemplatedEmail` for sending emails
- Create a Lambda function in the AWS Management Console
    - Runtime: `al2023provided.al2023`
    - Handler: `bootstrap`
    - IAM Role: Use the IAM Role created earlier
    - Environment Variables:
        - `KMS_KEY_ID`: KMS key ID for decrypting OPA policy
        - `POLICY_PATH`: S3 path to OPA policy
    - Code: Upload the ZIP archive
    - Permissions: Allow Cognito to invoke the Lambda function
- Configure Cognito to send Custom Email Sender events to the Lambda function
    - Configure the Cognito to use the same KMS key for encryption