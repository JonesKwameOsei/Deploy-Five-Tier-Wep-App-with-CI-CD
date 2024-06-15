# Set region
AWS_REGION="eu-west-1"

# Fetch username, password, and endpoint from SSM Parameter Store
DB_USERNAME=$(aws ssm get-parameter --region $AWS_REGION --name "/jones/euw1/username/username" --with-decryption --query "Parameter.Value" --output text)
DB_PASSWORD=$(aws ssm get-parameter --region $AWS_REGION --name "/jones/euw1/password/password" --with-decryption --query "Parameter.Value" --output text)
DB_ENDPOINT=$(aws ssm get-parameter --region $AWS_REGION --name "/jones/euw1/endpoint/endpoint" --query "Parameter.Value" --output text)

# Output the fetched values for debugging purposes (remove in production)
echo "DB Username: $DB_USERNAME"
echo "DB Password: $DB_PASSWORD"
echo "DB Endpoint: $DB_ENDPOINT"

# Connect Instance to the MySQL database
mysql -h $DB_ENDPOINT -u $DB_USERNAME -p$DB_PASSWORD -e "SHOW DATABASES;"