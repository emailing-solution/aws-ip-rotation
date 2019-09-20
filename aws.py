import json
import boto3
from botocore.exceptions import ClientError
import json
import sys
import time
import logging
from concurrent.futures.thread import ThreadPoolExecutor

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')


def cleanup():
    """ Cleanup elastic IPs that are not being used """
    addresses_dict = client.describe_addresses()
    for eip_dict in addresses_dict['Addresses']:
        if "InstanceId" not in eip_dict:
            logging.info(eip_dict['PublicIp'] +" doesn't have any instances associated, releasing")
            try:
                client.release_address(AllocationId=eip_dict['AllocationId'])
            except ClientError as e:
                logging.info("Failed releasing this ip "+eip_dict['PublicIp']+" "+str(e))

def start_thread(server_id):
    response = client.describe_network_interfaces(Filters=[{'Name': 'attachment.instance-id', 'Values': [server_id]}])
    # Loop through each IP
    logging.info("ASSIGN EIPS FOR INSTANCE "+str(server_id))
    for ip in response['NetworkInterfaces']:
        for j in ip['PrivateIpAddresses']:
            if j['Primary']:
                alloc = client.describe_addresses(Filters=[{'Name': 'private-ip-address', 'Values': [j['PrivateIpAddress']]}])
                if len(alloc['Addresses']) == 0:
                    logging.info("NO PRIMARY EIP ASSIGNED SIGNING NOW")
                    try:
                        allocation = client.allocate_address(Domain='vpc')
                        response = client.associate_address(AllocationId=allocation['AllocationId'], NetworkInterfaceId=ip['NetworkInterfaceId'], PrivateIpAddress=j['PrivateIpAddress'])
                    except ClientError as e:
                        logging.info(str(e))
            else:
                try:
                    allocation = client.allocate_address(Domain='vpc-ce0738a6')
                    response = client.associate_address(AllocationId=allocation['AllocationId'], NetworkInterfaceId=ip['NetworkInterfaceId'], PrivateIpAddress=j['PrivateIpAddress'])
                except ClientError as e:
                    logging.info(str(e))
    logging.info("ENDED ASSIGN IPS FOR INSTANCE "+str(server_id))

def start():
    servers = []
    logging.info("STARTING SERVERS FUNCTION")
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}])
    for instance in instances:
        servers.append(instance.id)

    with ThreadPoolExecutor(max_workers=10) as executor:
        for server in servers:
            executor.submit(start_thread, server)

    logging.info("ENDED ASSIGN IPS STARTING SERVERS" + str(servers))
    try:
        client.start_instances(InstanceIds=servers)
    except ClientError as e:
        logging.info("FAILED STARTING SERVERS "+ str(e))

def stop_thread(server_id):
    response = client.describe_network_interfaces(Filters=[{'Name': 'attachment.instance-id', 'Values': [server_id]}])
    logging.info("REMOVE EIPS FROM INSTANCE "+str(server_id))
    for ip in response['NetworkInterfaces']:
        for j in ip['PrivateIpAddresses']:
            if j['Primary'] == False:
                # Fetch AllocationId of EIP per SecondaryIp
                alloc = client.describe_addresses(Filters=[{'Name': 'private-ip-address', 'Values': [j['PrivateIpAddress']]}])
                for aid in alloc['Addresses']:
                    disassociateeip = client.disassociate_address(PublicIp=aid['PublicIp'])
                    releaseeip = client.release_address(AllocationId=aid['AllocationId'])
    logging.info("DONE REMOVING EIPS FROM INSTANCE "+str(server_id))

def stop():
    servers = []
    logging.info("STOPING SERVERS...")
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    for instance in instances:
        servers.append(instance.id)
       
    with ThreadPoolExecutor(max_workers=10) as executor:
        for server in servers:
            executor.submit(stop_thread, server)

    logging.info("ENDED RELEASE EIP STOPING SERVERS NOW" + str(servers))
    try:
        client.stop_instances(InstanceIds=servers)
    except ClientError as e:
        logging.info("FAILED STOPPING SERVERS "+ str(e))


def rotation_thread(server_id):
    logging.info("started rotation server "+server_id)
    response = client.describe_network_interfaces(Filters=[{'Name': 'attachment.instance-id', 'Values': [server_id]}])
    for ip in response['NetworkInterfaces']:
        for j in ip['PrivateIpAddresses']:
            if j['Primary'] == False:
                alloc = client.describe_addresses(Filters=[{'Name': 'private-ip-address', 'Values': [j['PrivateIpAddress']]}])
                for aid in alloc['Addresses']:
                    disassociateeip = client.disassociate_address(PublicIp=aid['PublicIp'])
                    releaseeip = client.release_address(AllocationId=aid['AllocationId'])
                    try:
                        allocation = client.allocate_address(Domain='vpc')
                        response = client.associate_address(AllocationId=allocation['AllocationId'], NetworkInterfaceId=ip['NetworkInterfaceId'], PrivateIpAddress=j['PrivateIpAddress'])
                    except ClientError as e:
                        logging.info(e)
    logging.info("ended rotation server "+server_id)


def rotate():
    servers = []
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    for instance in instances:
        servers.append(instance.id)

    if len(servers) > 0:
        logging.info("ROTATE SERVERS...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            for server in servers:
                executor.submit(rotation_thread, server)
    else:
        logging.info("NO RUNNING SERVERS FOUND FOR ROTATION")


access_key = sys.argv[1]
secrete_key = sys.argv[2]
region = sys.argv[3]

client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secrete_key, region_name=region)
ec2 = boto3.resource('ec2', aws_access_key_id=access_key, aws_secret_access_key=secrete_key, region_name=region)

while 1:
    cleanup()
    stop()
    logging.info("sleeping for 30 second")
    time.sleep(30)
    start()
    logging.info("sleeping 90 second")
    time.sleep(90)
    rotate()
    logging.info("sleeping 40 second")
    time.sleep(40)
    rotate()
    logging.info("sleeping 30 second")
    time.sleep(30)
