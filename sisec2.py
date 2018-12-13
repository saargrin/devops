import ConfigParser
import pymysql
import boto3
import time
import boto.vpc
from botocore.exceptions import ClientError
from ipaddress import IPv4Network
import pprint
import CloudFlare
import string
import random

config = ConfigParser.ConfigParser()
config.read("/etc/ansible/.rundeck.conf")
hostname = 'il-rundeck01'
musername = config.get("rundeck", "username")
password = config.get("rundeck", "password")
database = config.get("rundeck", "database")
cfuser = config.get('cloudflare', 'cfuser')
cfpassword = config.get('cloudflare', 'cfpassword')
try:
 dbc = pymysql.connect(host=hostname, user=musername, passwd=password, db=database)
 cur = dbc.cursor()
except pymysql.InternalError as error:
 code, message = error.args
 print ">>>>>>>>>>>>>", code, message



def getNameFromReg(region):
 regions = {"ap-northeast-1":"Tokyo", "ca-central-1":"Canada", "us-west-1":"California", "us-west-2":"Oregon", "us-east-1":"Virginia", "us-east-2":"Ohio", "eu-central-1":"Frankfurt", "eu-west-1":"Ireland", "eu-west-2":"London", "eu-west-3":"Paris", "ap-southeast-1":"Singapore", "ap-southeast-2":"Sydney", "ap-south-1":"Mumbai", "sa-east-1":"Sao Paulo"}
 return (regions[region])


def getAMI(client, ownerid):
    amiid = "NA"
    response = client.describe_images(Owners=[ownerid])
    images = response['Images']
    for image in images:
        if (image['Description'] == 'ready_4_ansible_and_AD'):
            amiid = image['ImageId']
            return (amiid)
        else:
            continue    

def createInstance(customer,ec2,client,amiid,itype,region,subnetid,sgid,disksize):
 disksize = int(disksize)
 bdm  = [
         {
             'DeviceName': '/dev/sda1',
             'Ebs': {
                 'DeleteOnTermination': True,
                 'VolumeSize': disksize,
                 'VolumeType': "gp2"
             },
         },
     ]

 instance = ec2.create_instances(ImageId=amiid,MinCount=1,MaxCount=1,InstanceType=itype,BlockDeviceMappings=bdm,NetworkInterfaces=[{'SubnetId': subnetid, 'DeviceIndex': 0, 'AssociatePublicIpAddress': True, 'Groups': [sgid]}])
 ec2.create_tags(Resources=[instance[0].id], Tags=[{'Key':'Name', 'Value': customer},{'Key':'Status','Value':'prod'}])
 volumes = instance[0].volumes.all()
 tags = [{'Key':'Name','Value': customer}]
 for volume in volumes:
  myvolume = ec2.Volume(volume.id)
  ec2.create_tags(Resources=[myvolume.id], Tags=tags)


 eip = client.allocate_address (Domain='vpc')
 instance[0].wait_until_running();
 client.associate_address(InstanceId = instance[0].id, AllocationId = eip["AllocationId"])
 client.modify_instance_attribute(InstanceId=instance[0].id,Attribute="disableApiTermination", Value="True")

 return (instance[0], eip["PublicIp"])





def createCF(customer,eip):
 print "Create record:",customer
 new_record = {
  'type':"A",
  'content':eip,
  'name':customer,
 }
 zone_name= "sisense.com"
 cf = CloudFlare.CloudFlare(email=cfuser,token=cfpassword)
 zones = cf.zones.get(params = {'name':zone_name})
 zone_id = zones[0]['id']
 zone_name = zones[0]['name']
 print zone_id, zone_name
 dns_records = cf.zones.dns_records.get(zone_id,params={'name':customer + '.' + zone_name})
 if dns_records:
  print "already exists",customer
 else:
  try:
   r = cf.zones.dns_records.post(zone_id, data=new_record)
   print "created",r['id']
   return (r['id'])
  except Exception as e:
   print e
   return (False)



     


def createIG(subnet_name,region):
 ec2 = boto3.resource('ec2',region_name=region)    
 ig  = ec2.create_internet_gateway()
 ig.create_tags (Tags = [ { 'Key': 'Name', 'Value': subnet_name }, ] )
 return (ig)

def createVPC(region,ig,cidr_vpc,subnet_name,vpcname,ec2,client):

 #ec2 = boto3.resource('ec2',region_name=region)
 vpc = ec2.create_vpc(CidrBlock=cidr_vpc,AmazonProvidedIpv6CidrBlock=True)
 vpc.create_tags(Tags = [ { 'Key': 'Name', 'Value': vpcname }, ])
 vpc.wait_until_available()   
 vpc.attach_internet_gateway(InternetGatewayId=ig.id) 
 client.modify_vpc_attribute( VpcId = vpc.id , EnableDnsSupport = { 'Value': True } )
 client.modify_vpc_attribute( VpcId = vpc.id , EnableDnsHostnames = { 'Value': True } )
 return (vpc)



def createSubnet(vpc,cidr_ext,subnet_name,region,az):
 ec2 = boto3.resource('ec2',region_name=region)
 subnet = vpc.create_subnet( AvailabilityZone=str(region+az),CidrBlock=cidr_ext )
 subnet.create_tags  (Tags = [ { 'Key': 'Name', 'Value': subnet_name }, ] ) 
 return (subnet)

def addSubnet(ec2,vpc_id,cidr_ext,subnet_name,region,az):
    for vpc in ec2.vpcs.all():
        #print vpc_id,vpc.id
        if vpc.id == vpc_id:
            subnet = vpc.create_subnet( AvailabilityZone=str(region+az),CidrBlock=cidr_ext )
            print subnet
            subnet.create_tags  (Tags = [ { 'Key': 'Name', 'Value': subnet_name }, ] ) 
            return (subnet)

def createSec(region,vpc,subnet_name):
 ec2 = boto3.resource('ec2',region_name=region)
 sg = ec2.create_security_group(GroupName=subnet_name,Description=subnet_name,VpcId=vpc.id)
 return (sg)

def addSGRules(sg,source,startport,endport):
 result = sg.authorize_ingress(CidrIp = source,IpProtocol='tcp',FromPort=int(startport),ToPort=int(endport))  
 return (result)

def addSGICMP (sg,source):
    result = sg.authorize_ingress(CidrIp = source,IpProtocol='icmp',FromPort=0,ToPort=8)  
    return (result)

def addSGRulesEgress(sg,source,startport,endport,proto):
 startport = int(startport)   
 endport = int(endport)
 
 result = sg.authorize_egress(
    IpPermissions=[
        {
            'IpProtocol': proto,
            'FromPort': startport,
            'ToPort': endport,
            'IpRanges': [
                {'CidrIp': source}
            ]
        }
    ]
)
 return (result)     

def revokeSGRulesEgress(sg):
 result = sg.revoke_egress(
    IpPermissions=[
        {
            'IpProtocol': "-1",
            'IpRanges': [
                {'CidrIp': "0.0.0.0/0"}
            ]
        }
    ]
)
 result = sg.revoke_egress(
    IpPermissions=[
        {
            'IpProtocol': "-1",
            'Ipv6Ranges': [
                {'CidrIpv6': "::/0"}
            ]
        }
    ]
)
 return (result)   

    

def addRoute(vpc,ig,subnet,subnet_name,region):
 client = boto3.client('ec2',region_name=region)  
 ec2 = boto3.resource('ec2',region_name=region)
 pubRouteTable = ec2.create_route_table( VpcId = vpc.id )
 pubRouteTable.associate_with_subnet( SubnetId  = subnet.id)
 pubRouteTable.create_tags (Tags = [ { 'Key': 'Name', 'Value': subnet_name }, ])
 #print 'RT:',pubRouteTable.id
 time.sleep(1)
 intRoute = client.create_route ( RouteTableId = pubRouteTable.id , DestinationCidrBlock = '0.0.0.0/0' , GatewayId = ig.id )
 return (pubRouteTable)

def getSerial(region):
 query = "select max(serial) from VPC where region=%s"  
 try:
  cur.execute( query,(region))
  data = cur.fetchone()
  if ( data[0] == None):
    cidr_serial = 0
  else:
    cidr_serial = int(data[0])
 except pymysql.InternalError as error:
  code, message = error.args
  print "MYSQL Error>>>>>>>>>>>>>", code, message  
 return(cidr_serial)

def updateSerial(customer,region,vpcid,subnetid,cidr):
 serial = getSerial(region)
 serial = int( int(serial)  + 1)
 print "new serial",serial
 query = "insert ignore into `VPC` (`vpcid`,`region`,`subnetid`,`subnet`,`customer`,`serial`) values (%s,%s,%s,%s,%s,%s);"
 try:
  cur.execute( query,(vpcid,region,subnetid,cidr,customer,serial))
  dbc.commit()
  return(True)
 except pymysql.InternalError as error:
  code, message = error.args
  print "MYSQL Error>>>>>>>>>>>>>", code, message  
  return(False)   


def createBasicSG(sg):
 print "Adding SG rules"   
 #RDP
 addSGRules(sg,"31.154.168.226/32","3389","3389")
 addSGRules(sg,"82.81.87.228/32","3389","3389")
 addSGRules(sg,"194.105.144.15/32","3389","3389")
 addSGRules(sg,"81.218.254.2/32","3389","3389")
 addSGRules(sg,"98.0.131.178/32","3389","3389")
 addSGRules(sg,"216.2.142.242/32","3389","3389")
 addSGRules(sg,"216.0.197.218/32","3389","3389")
 #WINRM
 addSGRules(sg,"82.81.87.228/32","5985","5985")
 addSGRules(sg,"82.81.87.228/32","5986","5986")
 #FTP
 addSGRules(sg,"82.81.87.228/32","990","990")
 addSGRules(sg,"31.154.168.226/32","990","990")
 addSGRules(sg,"81.218.254.2/32","990","990")
 addSGRules(sg,"194.105.144.15/32","990","990")
 addSGRules(sg,"98.0.131.178/32","990","990")
 addSGRules(sg,"216.2.142.242/32","990","990")
 addSGRules(sg,"216.0.197.218/32","990","990")
 #FTP4000
 addSGRules(sg,"82.81.87.228/32","4000","4100")
 addSGRules(sg,"31.154.168.226/32","4000","4100")
 addSGRules(sg,"81.218.254.2/32","4000","4100")
 addSGRules(sg,"194.105.144.15/32","4000","4100")
 addSGRules(sg,"98.0.131.178/32","4000","4100")
 addSGRules(sg,"216.2.142.242/32","4000","4100")
 addSGRules(sg,"216.0.197.218/32","4000","4100")
 #web
 addSGRules(sg,"82.81.87.228/32","8443","8444")
 addSGRules(sg,"31.154.168.226/32","8443","8444")
 addSGRules(sg,"81.218.254.2/32","8443","8444")
 addSGRules(sg,"194.105.144.15/32","8443","8444")
 addSGRules(sg,"98.0.131.178/32","8443","8444")
 addSGRules(sg,"216.2.142.242/32","8443","8444")
 addSGRules(sg,"216.0.197.218/32","8443","8444")
 #https
 addSGRules(sg,"0.0.0.0/0","443","443")
 #outbound
 revokeSGRulesEgress(sg)
 addSGRulesEgress(sg,"0.0.0.0/0","443","443","tcp")
 addSGRulesEgress(sg,"0.0.0.0/0","80","80","tcp")
 addSGRulesEgress(sg,"54.75.238.143/32","8080","8080","tcp") #GEO
 addSGRulesEgress(sg,"172.31.24.57/32","0","65535","tcp")#DC
 addSGRulesEgress(sg,"172.31.24.57/32","0","65535","udp")#DC
 addSGRulesEgress(sg,"172.31.9.105/32","0","65535","tcp")#DC
 addSGRulesEgress(sg,"172.31.9.105/32","0","65535","udp")#DC

 #nagios
 addSGICMP(sg,"69.9.33.76/32") #ICMP
 addSGRules(sg,"69.9.33.76/32","8443","8444") #nagios
 addSGRules(sg,"69.9.33.76/32","5666","5666") #nagios
 addSGRules(sg,"69.9.33.76/32","12489","12489") #nrpe
 addSGRules(sg,"69.9.33.76/32","5985","5986") #winrm




def updateLogins(customer,logins):
 query = "update `rundeck`.`instances` set `logins`= %s  where CustomerName = %s;" 
 try:
  cur.execute( query,(logins,customer))
  dbc.commit()
  return(True)
 except pymysql.InternalError as error:
  code, message = error.args
  print "MYSQL Error>>>>>>>>>>>>>", code, message  
  return(False)  


def peerToAD(vpcid,region,ownerid):
 client = boto3.client('ec2',region_name=region)
 dest_client = boto3.client('ec2',region_name="us-east-2")
 connectionid = client.create_vpc_peering_connection(VpcId=vpcid,PeerVpcId=str('vpc-9ae11ff3'),PeerOwnerId=str(ownerid),PeerRegion="us-east-2",)
 pcx = connectionid['VpcPeeringConnection']['VpcPeeringConnectionId']
 ex = False
 while (not ex):
  try:
   status = client.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx])['VpcPeeringConnections'][0]['Status']['Message']
   print pcx,"connection status",status
   ex = True
  except Exception as e:
   print pcx,"Not ready"    
   continue
 ex = False
 while (not ex):
  try:   
   status = dest_client.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx])['VpcPeeringConnections'][0]['Status']['Message']
   print "DEST:",pcx,"connection status",status
   ex = True
  except Exception as e:
   print "cant find ",pcx    
   continue

 connect = dest_client.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx)
 print "PCX Accept status:",connect['VpcPeeringConnection']['Status']
 return (pcx)

def get_main_route_table(self):
    """Return the main (default) route table for VPC."""
    main_route_table = []
    for route_table in list(self.route_tables.all()):
        for association in list(route_table.associations.all()):
            if association.main == True:
                main_route_table.append(route_table)
    if len(main_route_table) != 1:
        raise Exception('cannot get main route table! {}'.format(main_route_table))
    return main_route_table[0]


def addPeerRoute (main_cidr,vpc,pcx,ec2,ig,subnet,cidr_vpc):
 route_tables_with_main_association = ec2.route_tables.filter(Filters=[{'Name': 'association.main', 'Values': ["true"]},{'Name':'vpc-id','Values':[vpc.id]}]) 
 for rt in route_tables_with_main_association:
  rtx = rt.create_route(DestinationCidrBlock=main_cidr, VpcPeeringConnectionId=pcx)
  rtd = rt.create_route(DestinationCidrBlock = '0.0.0.0/0' , GatewayId = ig.id)
  rt.associate_with_subnet(SubnetId=subnet.id)
  print "peer",rtx,"default",rtd
 ec2 = boto3.resource('ec2',region_name="us-east-2")    
 destvpc = "vpc-9ae11ff3"  
 destrt  = ec2.route_tables.filter(Filters=[{'Name':'vpc-id','Values':[destvpc]}]) 
 for rt in destrt:
  if rt.id == "rtb-15c8317c" :
   print "adding to rtb-15c8317c"   
   destrtx = rt.create_route(DestinationCidrBlock=cidr_vpc, VpcPeeringConnectionId=pcx)
 print destrtx 
 return (rt)



def updateDb ( name,awsregion,regionName,itype,ip,vpc,sg,id,amiid,subnet,updated,disksize):
 print       "updating DB with: region",regionName,"name :",name#,itype,ip,vpc,sg,id,amiid,subnet,disk,snaps,az,version,updated,sfurl
 indb = checkInDb(name,regionName)
 try:
  dbc  = pymysql.connect( host=hostname, user=musername, passwd=password, db=database )
  cur=dbc.cursor()
 except pymysql.InternalError as error:
  code, message = error.args
  print ">>>>>>>>>>>>>", code, message
 if indb: 
  print name,"Already in DB" 
  try:
   query = "update `rundeck`.`instances` set `AWSRegion` = %s,`RegionName` = %s,`InstanceType`= %s, `ElasticIP` = %s,`VPC` = %s,`SecurityGroup` = %s,`InstanceID`= %s,`updated`= %s, `Disks`=%s where CustomerName = %s;" 
   cur.execute( query,(awsregion,regionName,itype,ip,vpc,sg,id,updated,disksize,name))
   dbc.commit()
  except pymysql.InternalError as error:
   code, message = error.args
   print ">>>>>>>>>>>>>", code, message
 if not indb:
  print "Will insert in DB ",name     
  try:  
   query = "insert into `rundeck`.`instances` (`CustomerName`,`AWSRegion`,`RegionName`,`InstanceType`,`ElasticIP`,`VPC`,`SecurityGroup`,`InstanceID`,`AMIID`,`SubnetID`,`updated`,`Disks`) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
   cur.execute (query,(name,awsregion,regionName,itype,ip,vpc,sg,id,amiid,subnet,updated,disksize))
   dbc.commit()
  except pymysql.InternalError as error:
   code, message = error.args
   print ">>>>>>>>>>>>>", code, message


def setAnsibleHosts(eip):
    
 fout = open ('/rundeck/ansible/hosts','w')
 print >> fout,"[win]"
 print >> fout,eip
 print >> fout,"[ec2server]"
 print >> fout,eip
 fout.close()
 
def pw_gen(size = 11, chars=string.ascii_letters + string.digits):
        schars  = "!@#-=*"
        pw = ''.join(random.choice(chars) for _ in range(size))
        pws =  ''.join(random.choice(schars) for _ in range(1))
        pwn = "".join(random.choice(string.digits) for _ in range(1))
        pwd = str(pw+pwn+pws)
        return (pwd)


  

def checkInDb(vmname,regionName):
     #print "Checking if already in DB ",vmname," Region ",regionName
 try:
  dbc  = pymysql.connect( host=hostname, user=musername, passwd=password, db=database )
  cur=dbc.cursor()
 except pymysql.InternalError as error:
  code, message = error.args
  print ">>>>>>>>>>>>>", code, message
 try: 
  query = "select `CustomerName` from instances where CustomerName= %s and RegionName = %s"  
  cur.execute (query,[vmname,regionName])
  rows = cur.fetchall()
  if not rows :
        print "Not In DB"
        return (False)
  else: 
        print "Already in DB"      
        return (True)
 except pymysql.InternalError as error:
  code, message = error.args
  print (">>>>>>>>>>>>>", code, message)

def getIGfromVPC(client,vpc):
    try:
        response = client.describe_internet_gateways()
        for igw in response['InternetGateways']:
            if (igw['Attachments'][0]['VpcId'] == vpc):
                return (igw['InternetGatewayId'])
    except Exception as e:
        print "failed to get IGWs,",e
        return False        

def getSubnetFromVPC (ec2,client,vpc):
    filters = [{'Name':'tag:Name', 'Values':['*']}]
    vpc_subnets = []
    subnets = list(ec2.subnets.filter(Filters=filters))
    for subnet in subnets:
        response = client.describe_subnets(SubnetIds=[subnet.id])
        if ( response['Subnets'][0]['VpcId'] == vpc ):
             subnetaz = str(response['Subnets'][0]['AvailabilityZone'])[-1:]
             subnetcidr = str(response['Subnets'][0]['CidrBlock'])
             vpc_subnets.append([subnet.id,subnetaz,subnetcidr])
    return (vpc_subnets) 

def checkIfSubnetExists(vpc_subnets,az):
    isFound = False
    for vpc_subnet in vpc_subnets:
        if (vpc_subnet[1] == az):
            isFound = True  
    if (isFound):
        return (True)            
    else:    
        print "no subnets found in AZ", az
    

def getSGsfromVPC(client,customer):
    response = client.describe_security_groups()['SecurityGroups']
    sgs = []
    basicsg = str (customer+"-basic-security-group")
    custsg = str (customer+"-security-group")
    for sg in response:
        if (sg['GroupName'] == basicsg):
            sgs.insert(0,sg['GroupId'])
        if (sg['GroupName'] == custsg):  
            sgs.insert(1,sg['GroupId'])
    return (sgs)                
