import json
import sys
import requests
from getpass import getpass
from tkinter import *
from tkinter.filedialog import askopenfilename
import csv
from requests.packages.urllib3.exceptions import InsecureRequestWarning

#Disable Insecure Request Warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Requests a CSV file in format Name,Value,Type,Description
Tk().withdraw()
print("Select csv file with Object Information: ")
object_file = askopenfilename() 

# Requests FMC information from user
server = input("Enter FMC IP: ")
domain_uuid = input("Enter Domain UUID: ")

# Requests Username and Password from user 
username = input("Username: ")
password = getpass("Password: ")

# Remove both sets of ''' to be able to pass username and password via arguments when running program
'''
if len(sys.argv) > 1:
    username = sys.argv[1]

if len(sys.argv) > 2:
    password = sys.argv[2]
'''



r = None
headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = "https://" + server + api_auth_path

# Get Auth Token
try:
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("auth_token not found. Exiting...")
        sys.exit()
except Exception as err:
    print ("Error in generating auth token --> "+str(err))
    sys.exit()
 
headers['X-auth-access-token']=auth_token


print("")

# Generate output file name from input file name
output_file = object_file.split('.')[0] + "-IMPORTED.csv"

# POST OPERATION
with open(object_file) as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    #iterates over csv_reader object and stores values into variables
    for row in csv_reader:
        obj_name = row[0]
        obj_value = row[1]
        obj_type = row[2]
        obj_desc = row[3]
        # Checks the object type and sets the api path to the proper path for the type
        if obj_type == "Network":
            api_path = "/api/fmc_config/v1/domain/" + domain_uuid + "/object/networks"
        if obj_type == "Host":
            api_path = "/api/fmc_config/v1/domain/" + domain_uuid + "/object/hosts"
        if obj_type == "FQDN":
            api_path = "/api/fmc_config/v1/domain/" + domain_uuid + "/object/fqdns"
        if obj_type == "Range":
            api_path = "/api/fmc_config/v1/domain/" + domain_uuid + "/object/ranges"
        url = "https://" + server + api_path
        if (url[-1] == '/'):
            url = url[:-1]
        try:
            # REST call with SSL verification turned off, sets overridable to True if this is not what you want change it to False
            r = requests.post(url, data=json.dumps({'name':obj_name, 'value':obj_value, 'type':obj_type, 'description':obj_desc, 'overridable':True}), headers=headers, verify=False)
            status_code = r.status_code
            resp = r.text
            print("Status code is: "+str(status_code))
            # Checks status code, prints a summary on screen, saves values from the response to variables and writes them to a new CSV
            if status_code == 201 or status_code == 202:
                print ("Post was successful...")
                json_resp = json.loads(resp)
                new_id = json_resp["id"]
                print(obj_name + " - " + obj_value + " - " + new_id)
                out_row = []
                out_row.append(obj_name)
                out_row.append(obj_value)
                out_row.append(obj_desc)
                out_row.append(new_id)
                out_row.append(obj_type)
                with open(output_file, 'a', newline='') as out_file:
                    writer = csv.writer(out_file)
                    writer.writerow(out_row)
                print("")
            else :
                r.raise_for_status()
                print ("Error occurred in POST --> "+resp)
                out_row = []
                out_row.append(obj_name)
                out_row.append(obj_value)
                out_row.append("Error")
                with open(output_file, 'a', newline='') as out_file:
                    writer = csv.writer(out_file)
                    writer.writerow(out_row)
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> "+str(err))
            out_row = []
            out_row.append(obj_name)
            out_row.append(obj_value)
            out_row.append("Error")
            with open(output_file, 'a', newline='') as out_file:
                writer = csv.writer(out_file)
                writer.writerow(out_row)
        finally:
            if r: r.close()
