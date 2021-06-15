#!/usr/bin/python2

"""
Name: Main.py
Author: Hari Mummidi
Date: 04/27/2021
Version: 1.0
Updates:
     
"""

# Importing required libraries

from subprocess import call
from os import environ,getlogin,getcwd,path,mkdir
from socket import gethostname
from datetime import datetime
import json
import requests
import sys
import os
from config import intro_str,instructions, prod_url, dev_url, prod_server,dev_server,sasadm_path
# Initialzing variables for environment setup

hostname = gethostname()

environ['SSL_CERT_FILE'] = '/opt/sas/viya/config/SASSecurityCertificateFramework/cacerts/trustedcerts.pem'

ldap = getlogin()
cwd = getcwd()
logdir = cwd + "/log"

# Creating log directory in case neccessary to capture logs or debugging and audit of the console.
if path.isdir(logdir):
    pass
else:
    mkdir(logdir)

logfile = logdir + "pyadmin.log"

colors = {'R': '\003[1;31;40m','G' : '\003[1;32;40m', 'W' : '\003[1;37;40m', 'B' : '\003[1;34;40m'}

profile_env = {"Dev": "devviya", "Prod" : "prodviya"}
env_url = {"Dev" : dev_url, "Prod": prod_url}


open(logfile,'a').write("\n" + datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ":" + ldap + " Logged in from host " + hostname + "\n")

# Function to check the permissions on the file before opening

def file_accessible(filepath,mode):
    try:
        f = open(filepath,mode)
        f.close()
    except IOError as e:
        return False
    return True

def getbaseurl():

    # Check if the profile file is available and can be read

    endpointfile = "/home" + ldap + "/.sas/config.json"
    access_file = file_accessible(endpointfile,'r')

    # If profile doesn't exists
    if access_file == False:
        print("ERROR: Cannot read CLI Profile at: ", endpointfile, ". recreate profile")
        modules()

    # Profile is empty
    if os.stat(endpointfile).st_size == 0:
        print("ERROR: Cannot read CLI profile empty file at: ", endpointfile, "Recreate the profile ")
        modules()
    
    # Get json from profile
    with open(endpointfile) as json_file:
        data = json.load(json_file)
    
    cur_profile = profile_env[env]

    if cur_profile in data:
        baseurl=data[cur_profile]['sas-endpoint']
    else:
        baseurl = None
        print("ERROR: profile ", cur_profile, " doesn't exists. Please recreate the prodfile")
        modules()
    
    return baseurl


def createprofile():
    instr= """ %s
    Follow below steps for creation:

    1. Enter SAS VIYA Host Name %s
    2. Provide output type as json or
    3. Enable ANSI Color as n
    """
    print(instr % (colors['G'],env_url[env]))

    rc = call([sasadm_path + "/sas-admin","--profile ",profile_env[env],"profile","init"])

    if rc == 0:
        env_c = "%s " + env

        print("%s Profile has been created in your home profile under .sas folder for " % color['G'] + env_c % color['B'])
        open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ":" + "Created Profile for " + ldap + "\n")
        modules()

    else:
        open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ":" + "Failed to create profile for " + ldap + "in " + env) 
        print("%s Failed to create profile " % colors['R'])
        modules()

def checkprofile():

    baseurl = getbaseurl()
    
    if baseurl != None:
        print("Profile is available for " + env)
        modules()
    else:
        print("Profile not created, Please create")
        modules()

def createtoken():

    baseurl = getbaseurl()

    if baseurl == None:
        createprofile()
    else:
        instr = """%s
    Enter Username as SSO id and password to generate token
    This is valid for 12 hours only
        """
        print(instr % colors['G'])
        print('%s' & colors['W'])

        rc = call([sasadm_path + "/sas-admin", "--profile", profile_env[env],"auth", "login"])

        if rc == 0:
            open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ": Token created for " + ldap + "\n")
            modules()
        else:
            open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ": Failed to create token for " + ldap + "\n")
            modules()
        

# Space for creating authlogin function

def authinfo_token_creation():
    pass


def getaccesstoken():

    credentials_file = "/home" + ldap + "/.sas/credentials.json"

    if path.isfile(credentials_file):

        with open(credentials_file) as json_file:
            data = json.load(json_file)

        token = data[profile_env[env]]['access-token']

        if token == '':
            print("Please Create a token")
        else:
            return token
        
    else:
        print("Please login to create a token ")
        con = raw_input("Continoue to create profile Yes/No?")

        if con.upper() == "YES:
            createtoken()
        else:
            print("No Active Profile")
            modules()

def callrestapi(reqval,mode):
    token = getaccesstoken()
    acceptType = "application/json"
    contenttype = "application/json"

    headers = {'Content-type': contenttype, 'Accept' : acceptType,
                'Authorization' : 'Bearer ' + str(token),
                'Accept-Language' : 'string'}
    baseurl = getbaseurl()
    if mode == 'get':
        rc = requests.get(baseurl + reqval, params= {} , headers=headers, verify=False)
    elif mode == 'put':
        rc = requests.put(baseurl + reqval, params= {} , headers=headers, verify=False)
    if (400 <= rc.status_code <= 599):
        print(ret.text)
        modules()
    
    return rc

def getgroups():

    js_data = callrestapi(r"/identities/groups?providerID=local&limit=10000")
    js_data = js_data.json()
    groups = js_data['items']
    group_dict = {}
    for group in groups:
        group_dict.update({group['name']: group['id']})
    
    return group_dict

def checkusergroup(sso,group):

    reqval = r"/identities/users/" + str(sso) + r"/memberships/"
    js_data = callrestapi(reqval,'get')

    memships = js_data['items']

    for mem in memships:
        if mem['id'] == group:
            print("User is already part of group")
            return True
        else:
            False

def adduser(group,sso):

   reqval = r"/identities/groups/" + group + r"/userMembers/" + str(sso) + r"/"
   rc = callrestapi(reqval,'put')

   if rc.status_code == 201:
       print("User added successfully to ", group)
       open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ": User " + str(sso) + "added sucessfully to " + group + "\n")
       modules()
   else:
       print("ERROR: Unable to add user to", group ,r.status_code)
       open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ":ERROR: Unable to add User " + str(sso) + " to " + group + "\n")
       modules()

def logout():
    
    call([sasadm_path + "/sas-admin","--profile",profile_env[env],"auth","logout"])
    open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ": " + ldap + "logged out" + "\n")
    print("%s Thanks for using VIYA PyAdmin Console " % colors['G'])
    print("%s" % colors['W'])
    sys.exit()

def addbulkusers(group,path):

    open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ": Adding bulk users to " + group + "\n")
    is_accessable = file_accessible(path,'r')

    if is_accessable:
        users = open(path,'r').read()
        users_list = users.split("\n")

        for sso in users_list[:-1]:
            adduser(group,sso)
    else:
        print("Unable to open the file ", path)

    modules() 



def user_list_group(group):

    open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ": Fetching users list based on group ID " + group + "\n")

    group_c = "%s" + group
    print("%s you have entered : " % colors['G'] + group_c % colors['B'])

    reqvql = r"/identities/groups/" + group + r"/members?limit=10000"

    js_data = callrestapi(reqval,'get')
    js_data = js_data.json()

    for user in users():
        print("SSO: " + users['id'] + "Name: " + user['name'])
    
    open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ": Completed Fetching users list based on group ID " + group + "\n")
           

            
    

def user_list_sso(sso):

    reqval = r"/identities/users/" + str(sso) + r"/memberships/"
    js_data = callrestapi(reqval,'get')

    memships = js_data['items']

    for mem in memships:
        # mem['id']
        print(mem['name'])


def execute(option):
    if option == 1:
        createprofile()
        modules()
    elif option == 2:
        checkprofile(ldap)
        modules()
    elif option == 3:
        createtoken()
        modules()
    elif option == 4:
        print("Select groups to be added from below \n")
        groups_dict = getgroups()
        for grp in groups_dict.keys():
            print(grp)

        group = raw_input("%s Enter Group to be added: " % colors['G'])
        ssoid = raw_input("%s Enter SSO Id of the user to be added: " % colors['G'])
        checkstat = checkusergroup(ssoid,groups_dict[group])

        if checkstat:
            modules()
        else:
            adduser(groups_dict[group],ssoid)
        modules()
    
    elif option == 5:

        group = raw_input("%s Enter group to be added: " % colors['G'])
        path = raw_input("%s Enter path of the file that has sso IDs to be added: " % colors['W'])
        addbulkusers(group,path)
        modules()
    
    elif option == 6:
        group  = raw_input("%s Enter group ID to get the users list \n >>>>>" % colors['G'])
        user_list_group(group)
        modules()
    elif option == 7:
        sso = raw_input("%s Enter SSO ID to get the membership List \n >>>>" % colors['G'] )
        user_list_sso(sso)
        modules()
    elif option == 8:
        logout()
    elif option == 9:
        print("%s Thanks for using VIYA PyAdmin Cosole " % colors['G'])
        open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ": Existing from console " + "\n")
        print("%s" % colors['W'])
        sys.exit()
    else:
        print("%s Select any one of the mentioned option " % colors['G'])
        modules()
    
def modules():
    option = input(instructions % color['G'])
    open(logfile,'a').write(datetime.now().strftime('%b, %m, %Y %H:%M:%S') + ": Selected option " +  str(option) + "\n")
    execute(option)


print(intro_str % colors['G'])

if hostname == dev_server:
    global env = "Dev"
    modules()
elif hostname == prod_server:
    global env = "Prod"
    modules()
else:
    print("%s Cannot run the console other than VIYA Server " % colors['R'])
    print("%s" % colors['W'])








        


    



    



