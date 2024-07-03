'''
Dallin Allred
Proof of Concept
AWS Resource Enumeration via Python SDK (Boto3)
'''

import argparse
import boto3
import datetime

class Dynamo:
  'Class for tracking DynamoDB data'
  def __init__(self):
    'Constructor'
    self.client = boto3.client('dynamodb')

  def list_dynamo(self):
    'Collect the desired DynamoDB data from AWS'
    tables = self.client.list_tables()['TableNames']
    table_metadata = []
    for table in tables:
      temp = {'Name': table}
      desc = self.client.describe_table(TableName=table)['Table']
      temp['ARN'] = desc['TableArn']
      temp['CreationDate'] = desc['CreationDateTime'].strftime('%m-%d-%Y %H:%M:%S')
      temp['NumItems'] = desc['ItemCount']
      temp['DbSize (bytes)'] = desc['TableSizeBytes']
      table_metadata.append(temp)
    return table_metadata

  def write(self, report):
    'Output DynamoDB data to the supplied report file handle'
    print('Collecting DynamoDB Data')
    tables = self.list_dynamo()
    print('Writing DynamoDB Data')
    report.write('**DynamoDB**\n')
    headers = list(tables[0].keys())
    header_str = '\t'.join(headers)
    report.write(f'{header_str}\n')
    for table in tables:
      line = []
      for col in headers:
        line.append(str(table[col]))
      line = '\t'.join(line)
      report.write(f'{line}\n')

class EC2:
  '''
  Class for managing EC2
  '''
  def __init__(self):
    '''
    Constructor for EC2 class
    '''
    self.client = boto3.client('ec2')
    self.resource = boto3.resource('ec2')
  
  def elastic_ips(self):
    '''
    List all elastic IP addresses
    '''
    response = self.client.describe_addresses()
    return response['Addresses']

  def list_ec2(self):
    '''
    List all EC2 instances and group them by state
    '''
    running = []
    stopped = []
    other = []
    for instance in self.resource.instances.all():
      if instance.state['Name'] == 'running':
        running.append(instance)
      elif instance.state['Name'] == 'stopped':
        stopped.append(instance)
      else:
        other.append(instance)
    return running, stopped, other

  def stop(self, exclude_tags):
    running, stopped, other = self.list_ec2()
    exclude = set(exclude_tags)
    stopping = []
    for instance in running:
      inst_tags = {tag['Key']: tag['Value'] for tag in instance.tags}
      tag_keys = set(inst_tags.keys())
      intersection = tag_keys.intersection(exclude)
      if len(intersection) > 0:
        continue
      stopping.append(instance.id)
    self.client.stop_instances(InstanceIds=stopping)
  
  def write(self, report):
    print('Collecting EC2 Data')
    running, stopped, other = self.list_ec2()
    print('Writing EC2 Data')
    report.write('**EC2 Information**\n')
    report.write('Running EC2 Instances\n')
    report.write('InstanceId\tState\tUptime\tInstanceType\tTags\n')
    for instance in running:
        now = datetime.datetime.now().astimezone()
        uptime = now - instance.launch_time
        report.write(f'{instance.id}\t{instance.state["Name"]}\t{uptime}\t{instance.instance_type}\t{instance.tags}\n')
    report.write('\nStopped Instances\n')
    report.write('InstanceId\tState\tInstanceType\tTags\n')
    for instance in stopped:
      report.write(f'{instance.id}\t{instance.state["Name"]}\t{instance.instance_type}\t{instance.tags}\n')

    if len(other) > 0:
      report.write('\nOther Instances\n')
      report.write('InstanceId\tState\tInstanceType\tTags\n')
      for instance in other:
        report.write(f'{instance.id}\t{instance.state["Name"]}\t{instance.instance_type}\t{instance.tags}\n')
    print('Collecting Elastic IP Data')
    elastic_ips = self.elastic_ips()
    print('Writing Elastic IP Data')
    if len(elastic_ips) > 0:
      report.write('\nInstances with Elastic IP Addresses\n')
      report.write('InstanceId\tAllocationId\tAssociationId\n')
      for ip in elastic_ips:
        report.write(f'{ip["InstanceId"]}\t{ip["AllocationId"]}\t{ip["AssociationId"]}\n')

class Lambda:
  'Class for interacting with AWS Lambda'
  def __init__(self):
    'Constructor to initialize lambda and logs Boto3 clients'
    self.client = boto3.client('lambda')
    self.logs = boto3.client('logs')

  def list_lambda(self):
    'List desired AWS lambda data'
    func_data = []
    result = self.client.list_functions()
    for func in result['Functions']:
      temp = {}
      temp['FuncName'] = func['FunctionName']
      temp['ARN'] = func['FunctionArn']
      temp['LastModified'] = func['LastModified']
      temp['Version'] = func['Version']
      try:
        log_grp = func['LoggingConfig']['LogGroup']
        stream = self.logs.describe_log_streams(
          logGroupName=log_grp,
          orderBy='LastEventTime',
          limit=1
        )
        last_event = stream['logStreams'][0]['lastEventTimestamp']
        last = datetime.datetime.fromtimestamp(last_event/1000)
        last = last.strftime('%Y-%m-%dT%H:%M:%S')
        temp['LastEventLogged'] = last
      except Exception as e:
        temp['LastEventLogged'] = func['LastModified']

      func_data.append(temp)
    func_data = sorted(func_data, key=lambda el: el['LastModified'])
    return func_data

  def write(self, report):
    'Output Lambda data to the supplied report file handle'
    print('Collecting Lambda Data')
    funcs = self.list_lambda()
    print('Writing Lambda Data')
    report.write('**Lambda**\n')
    headers = list(funcs[0].keys())
    header_str = '\t'.join(headers)
    report.write(f'{header_str}\n')
    for func in funcs:
      line = []
      for col in headers:
        line.append(func[col])
      line = '\t'.join(line)
      report.write(f'{line}\n')

class RDS:
  'Class for interacting with AWS RDS'
  def __init__(self):
    'Constructor to initialize an RDS Boto3 client'
    self.client = boto3.client('rds')

  def list_rds(self):
    'List existing RDS instances and desired data'
    response = self.client.describe_db_instances()['DBInstances']
    rds_data = []
    for db in response:
      temp = {
        'DB Instance': db['DBInstanceIdentifier'],
        'CreateTime': db['InstanceCreateTime'],
        'Status': db['DBInstanceStatus'],
        'Class': db['DBInstanceClass'],
        'Engine': db['Engine'],
        'Storage': db['StorageType']
      }
      rds_data.append(temp)
    return rds_data
      
  def write(self, report):
    'Output RDS data to the supplied report file handle'
    print('Collecting RDS Data')
    tables = self.list_rds()
    print('Writing RDS Data')
    report.write('**RDS**\n')
    headers = list(tables[0].keys())
    header_str = '\t'.join(headers)
    report.write(f'{header_str}\n')
    for table in tables:
      line = []
      for col in headers:
        line.append(str(table[col]))
      line = '\t'.join(line)
      report.write(f'{line}\n')

class S3:
  'Class for tracking S3 data'
  def __init__(self):
    'Constructor to initialize an S3 Boto3 client'
    self.client = boto3.client('s3')

  def list_s3(self):
    '''
    List all S3 buckets in ascending order of creation date
    '''
    response = self.client.list_buckets()
    buckets = sorted(response['Buckets'], key=lambda el: el['CreationDate'])
    bucket_data = []
    for bucket in buckets:
      creation_date = bucket['CreationDate'].strftime('%m/%d/%Y %H_%M_%S')
      bucket_data.append({'created': creation_date, 'name': bucket['Name']})
    return bucket_data
  
  def write(self, report):
    'Output S3 data to the supplied report file handle'
    print('Collecting S3 Data')
    s3_buckets = self.list_s3()
    print('Writing S3 Data')
    report.write('**S3 Buckets**\n')
    report.write('Creation Date\tBucket Name\n')
    for bucket in s3_buckets:
      report.write(f'{bucket["created"]}\t{bucket["name"]}\n')
  

def write_report(resources, file=None):
  '''
  Write data to a .tsv file for review
  '''
  timestamp = datetime.datetime.now().strftime('%m-%d-%Y %H_%M_%S')
  filename = file
  if not file:
    filename = f'AWS_Report {timestamp}.tsv'
  report = open(filename, 'w')

  resource_map = {
    'dynamodb': Dynamo,
    'ec2': EC2,
    'Lambda': Lambda,
    'rds': RDS,
    's3': S3
  }

  if len(resources) == 0:
    for resource, constructor in resource_map.items():
      rsrc = constructor()
      rsrc.write(report)
      report.write('\n')
  else:
    for resource in resources:
      try:
        rsrc = resource_map[resource]()
        rsrc.write(report)
        report.write('\n')
      except KeyError as e:
        print(e)
        continue
  report.close()


def main():
  '''
  Main driver function
  Parses arguments. Default action is to generate a resource report
  '''

  parser = argparse.ArgumentParser(
    prog='aws.py',
    description='Enumerates allocated/running AWS services.\
      If no options are specified then all listed resources will be enumerated.',
    epilog='Dallin Allred - Apr. 2024')
  parser.add_argument('--dynamodb', action='store_true', help='Include DynamoDB in reporting')
  parser.add_argument('--ec2', action='store_true', help='Include EC2 in reporting')
  parser.add_argument('--Lambda', action='store_true', help='Include Lambda in reporting')
  parser.add_argument('--rds', action='store_true', help='Include RDS in reporting')
  parser.add_argument('--s3', action='store_true', help='Include S3 in reporting')
  parser.add_argument('-f', '--file', help='Specify an output file (.tsv)')
  args = parser.parse_args()

  resource_args = {
    'dynamodb': args.dynamodb, 'ec2': args.ec2, 'Lambda': args.Lambda, 'rds': args.rds, 's3': args.s3
    }
  resources = [el for el, val in resource_args.items() if val]

  write_report(resources, args.file)

if __name__ == '__main__':
  main()
