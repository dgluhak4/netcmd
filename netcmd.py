#!/usr/bin/python3
"""
Script connects to Cisco devices, gets some commands output and parses or repeats if needed

Usage: netcmd.py [-d|-l] <device(s)> [-c|-x] <command(s)> [OPTIONs]
-h --help Help screen
-d --device IP of the device OR -l --device_file_list file with the list of devices (mandatory)
-c --command single command to execute OR -x --cmd_file_list file with the list of commands per device (mandatory)
-r --repeat invoke repeat-based ot time-based re-issuing of single command or list of commands (default is 1/once, 0 for infinite, XXs for every XX seconds)
-p --parse choose to parse output using textfsm (default is not to parse)
-t --template choose to present output date defined in custom template (default is without template, all data is displayed or stored)
-q --query a string to search for in command(s) outputs (mandatory if template is \"grep\")
-b --bar choose to use progress bar while waiting for outputs (invalid when using -d and -c options)
-y --device_type choose device type (defines who expect module processes outputs from the device)
-v --timestamp put local timestamp on each output
-s --store choose if want to write command output to a file/files"
"""
import sys
import getopt
import os
import subprocess
import time
import json
#import readline
from getpass import getpass

# loading network library
from netmiko import Netmiko

# loading logging and preparing to log
import logging

# import additional device/command related functions
import NetDeviceFunc

# GLOBALS
HELP="Usage: netcmd.py [-d|-l] <device(s)> [-c|-x] <command(s)> [-j] <device+commands> [OPTIONs] \r\n \
COMMANDS:\r\n\r\n \
-h --help Help screen\r\n\r\n \
-d --device IP of the device OR -l --device_file_list file with the list of devices (mandatory)\r\n \
-c --command single command to execute OR -x --cmd_file_list file with the list of commands per device (mandatory)\r\n \
-j --json json formated file with list of devices and respected commands (one file for both device and command is used)\r\n \
OPTIONS:\r\n\r\n \
-r --repeat invoke repeat-based or time-based re-issuing of single command or list of commands (default is 1/once, 0 for infinite, XXs for every XX seconds)\r\n \
-p --parse choose to parse output using textfsm (default is not to parse)\r\n \
-t --template choose to present output date defined in custom template (default is without template, all data is displayed or stored)\r\n \
-q --query a string to search for in command(s) outputs (mandatory if template is \"grep\")\r\n \
-b --bar choose to use progress bar while waiting for outputs (invalid when using -d and -c options)\r\n \
-y --device_type choose device type (defines who expect module processes outputs from the device)\r\n \
-o --overwrite overwrite in-file provided username and password with the one taken from user input\r\n \
-v --timestamp put local timestamp on each output\r\n \
-s --store choose if want to write command output to a file/files\r\n"
SHOULD_PARSE = False #when True parsing to dictonary, default is not to parse
SHOULD_PROGRESS = False #when True display progress bar while executing multiple comamands on multiple devices, default is not to display progress bar
SHOULD_STORE = False #when True should write command output to a file named after host, default is to not store the output          
SHOULD_TIME = False #when True repeat value means timing in seconds between repetion of command execution
SHOULD_STAMP = False #when True put timestamp to every (set of) command(s) output from device
SHOULD_INFINITE = False #indicating that process of executing command(s) on device(s) is repeating indefinetly
SHOULD_OVERWRITE = False #indicating that in-file provided username and password has to be overwritten by the user input
custom_DIV='%'
default_TYPE="cisco_ios"
default_MODEL="custom"

# program exit function (with error message)
def exit_error(err_message="Unknown error"):

    print(err_message)
    print(HELP)
    sys.exit(2)

# populating device list and options
def prepare_device_data(cmd_options):
    global SHOULD_PARSE, SHOULD_PROGRESS, SHOULD_STORE, SHOULD_TIME, SHOULD_STAMP, SHOULD_INFINITE, SHOULD_OVERWRITE

    dev_params={"host_file_name":"","command_file_name":"","host_ip":"127.0.0.1","cmd":"","overwrite":SHOULD_OVERWRITE, \
        "user_device_type":default_TYPE,"invalid_option":{'Device':0,'Command':0},"option":{"Device":2,"Command":2}}
    sys_params={"repeat":1,"progress":SHOULD_PROGRESS,"store":SHOULD_STORE,"stamp": SHOULD_STAMP, \
        "time": SHOULD_TIME, "parse": SHOULD_PARSE, "datamodel":default_MODEL, "query_data":"", "template":"none", "infinite": False}
    dev_list=[]

    # analysis and prepraration of input arguments
    for curr_opts, curr_vals in cmd_options:
        if curr_opts in ("-h", "--help"):
            print(HELP)
            sys.exit(0)
        elif curr_opts in ("-p","--parse"):            
            sys_params["parse"] = True
        elif curr_opts in ("-b","--bar"):            
            sys_params["progress"] = True
        elif curr_opts in ("-s","--store"):            
            sys_params["store"] = True
        elif curr_opts in ("-v","--timestamp"):            
            sys_params["stamp"] = True
        elif curr_opts in ("-r","--repeat"):
            # if repeat parameter is a number
            if (curr_vals.isdigit()):
                sys_params['repeat']=eval(curr_vals)
                sys_params['time'] = False
                # for continuos and infinite command execution repetition, repeat = 65535
                if (sys_params["repeat"] == 0):                    
                    sys_params["repeat"] = 65535                    
                    sys_params['infinite'] = True
            # if repeat parameter is a string
            else:
                sys_params["repeat"]=eval(curr_vals[:len(curr_vals)-1])
                if (curr_vals[len(curr_vals)-1] == 's'):
                    sys_params['time'] = True
                elif (curr_vals[len(curr_vals)-1] == 'r'):
                    sys_params['time'] = False
                    # If there should be infinite command execution repetition
                    if (sys_params["repeat"] == 0):
                        SHOULD_INFINITE=True
                        sys_params["repeat"] = 65535

                else:
                    exit_error("Invalid repetion request")
        elif curr_opts in ("-t","--template"):            
            sys_params["parse"] = True
            sys_params["template"]=curr_vals
        elif curr_opts in ("-q","--query"):
            sys_params["query_data"]=curr_vals
        elif curr_opts in ("-o","--overwrite"):
            sys_params["overwrite"] = True
        elif curr_opts in ("-j","--json"):
            sys_params["datamodel"]="json"
            dev_params["host_file_name"]=curr_vals
            dev_params["invalid_option"]['Command'] +=1
            dev_params["invalid_option"]['Device'] +=1            
            dev_params["option"]['Device']=3
            dev_params["option"]['Command']=3
            #print (dev_params["host_file_name"])
            try:
                hostfile=open(dev_params['host_file_name'],'r')
            except FileNotFoundError as err:
                exit_error(err)
        elif curr_opts in ("-y","--device_type"):
            dev_params["user_device_type"]=curr_vals
        elif curr_opts in ("-d","--device"):
            dev_params["host_ip"]=curr_vals
            dev_params["invalid_option"]['Device'] += 1     
            dev_params["option"]['Device']=1
        elif curr_opts in ("-c","--command"):
            dev_params["cmd"]=curr_vals
            dev_params["invalid_option"]['Command'] +=1
            dev_params["option"]['Command']=1            
        elif curr_opts in ("-l","--device_file_list"):
            dev_params["host_file_name"]=curr_vals
            dev_params["invalid_option"]['Device'] += 1     
            dev_params["option"]['Device']=2
            try:
                hostfile=open(dev_params['host_file_name'],'r')
            except FileNotFoundError as err:
                exit_error(err)
        elif curr_opts in ("-x","--cmd_file_list"):
            dev_params["command_file_name"]=curr_vals
            dev_params["invalid_option"]['Command'] +=1
            dev_params["option"]['Command']=2
            try:
                cmdfile=open(dev_params['command_file_name'],'r')
            except FileNotFoundError as err:
                exit_error(err)
        else:
            print(HELP)
            sys.exit(2)
    if dev_params["invalid_option"]['Device'] != 1:
        exit_error("Too little or too many device options - should be only one")        
    if dev_params["invalid_option"]['Command'] != 1:
        exit_error("Too little or too many command options - should be only one")        
    if dev_params["invalid_option"]['Device']*dev_params["invalid_option"]['Command'] > 0:        
        sys_params['progress'] = False

    # provjera analize input argumenata
    #print (dev_params)
    #print (sys_params)
    # Getting username and password of user connecting to devices 
    dev_user = input("Input user name used to collect information from devices: ")
    #print ("Input user password used to connect to devices: ")
    dev_pass = getpass()
    # popunjavanje liste uredjaja
    cmdlineseq=[]
    # ako je samo jedan uredjaj iz prompta
    if (dev_params["option"]['Device']) == 1:
        hostline=dev_params['host_ip']+custom_DIV+dev_params['user_device_type']+custom_DIV+"SINGLE_DEVICE"
        temp_device=prepare_device(hostline,dev_user,dev_pass)        
        if (dev_params["option"]['Command']) == 1:
            temp_device['commands'].append(dev_params['cmd'])
        elif (dev_params["option"]['Command']) == 2:            
            # Populating command list for one device
            cmdline=cmdfile.readline()
            #print(cmdline)
            cmdlineseq=cmdline.split(custom_DIV)
            temp_device['commands']=cmdlineseq.copy()
            cmdfile.close()
        else:
            exit_error("JSON model not allowed in single device input parameter!")
        dev_list.append(temp_device)
    elif (dev_params["option"]['Device']) == 2:            
        if (dev_params["option"]['Command']) == 3:
            exit_error("JSON model not allowed in single device input parameter!")
        else:    
            for hostline in hostfile:
                cmdlineseq.clear()
                temp_device=prepare_device(hostline,dev_user,dev_pass)
                # Populating command list for current device
                if (dev_params["option"]['Command']) == 2: 
                    cmdline=cmdfile.readline()
                    #print(cmdline)
                    cmdlineseq=cmdline.split(custom_DIV)
                else:
                    cmdlineseq.append(dev_params['cmd'])
                temp_device['commands']=cmdlineseq.copy()
                dev_list.append(temp_device)      
            if (dev_params["option"]['Command']) == 2:   
                cmdfile.close()                        
        hostfile.close()
    elif (dev_params["option"]['Device']) == 3:
        # OPEN JSON FILE AND DO SOMETHING
        dev_list=json.load(hostfile)
        for dev in dev_list:
            if "username" in dev:
                if (len(dev["username"]) == 0) or dev_params['overwrite']:
                    dev["username"]=dev_user
            else:
                dev["username"]=dev_user
            if "password" in dev:
                if (len(dev["password"]) == 0) or dev_params['overwrite']:
                    dev["password"]=dev_pass
            else:
                dev["username"]=dev_pass
        #print (dev_list)
    else:
        exit_error("Invalid reference to device list!")

    return sys_params, dev_list

# Populating device with device properties
def prepare_device(hostline,dev_user,dev_pass):
        
    hostlineseq=hostline.split(custom_DIV)    
    #print (len(hostlineseq))
    #print (len(hostline))
    if (len(hostlineseq) == 3):
        hostlineseq.append(dev_user)
        hostlineseq.append(dev_pass)
    #print (hostlineseq)
    #print (hostline)
    curr_device = {
        'host': hostlineseq[0],
        #'device_type': 'cisco_ios'
        'device_type': hostlineseq[1][:len(hostline)-2],
        'name': hostlineseq[2],
        #'username': dev_user,
        #'password': dev_pass,        
        'username': hostlineseq[3],
        'password': hostlineseq[4],
        'secret': hostlineseq[4],
        #'global_delay_factor': 2
        'commands':[],
        'output':[]
    }
    if (curr_device['device_type'] == 'juniper'):
        curr_device['global_delay_factor'] = 2
    #elif (curr_device['device_type'] == 'linux'):
    #    curr_device['username'] = hostlineseq[3]
    #    curr_device['password'] = hostlineseq[4]
    #print (curr_device['username']," ",curr_device['password'])
    return curr_device

# core function    
def main(argumentList):
    """
Main function that deploys list of commands to a list of devices and parses and stores its output
    """
    global SHOULD_PARSE, SHOULD_PROGRESS, SHOULD_STORE, SHOULD_TIME, SHOULD_STAMP, SHOULD_INFINITE
    try:
        cmd_options, cmd_values = getopt.getopt(argumentList, "hpbsvoj:d:l:c:x:r:t:q:y:", ["help","parse","bar","store","overwrite","timestamp",\
            "json=","device_list=","device=","device_file_list=","command=","cmd_file_list=","repeat=","template=","query=","device_type="])
    except getopt.GetoptError:
        exit_error("Invalid input option!")
    logging.basicConfig(filename='test.log', level=logging.DEBUG)
    logger = logging.getLogger("netmiko")
    sys_params={}
    device_template={}  
    device_list=[]
    sys_params, device_list = prepare_device_data(cmd_options)
    print(sys_params)
    print(device_list)

    # Main loop        
    while ((sys_params['time'] or sys_params['infinite']) or sys_params['repeat']):     
        for device in device_list:
            #net_device = Netmiko(**device)
            output=""
            for cmd in device['commands']:
                #output = output+os.linesep+net_device.send_command_timing(cmds)
                output = output+os.linesep+cmd
                #if (SHOULD_PROGRESS):
                #    NetDeviceFunc.progress_bar()   
                print (output)
        if not sys_params['store']:
            print("Nema snimanja")
        else:
            print("Sada snimam jednu iteraciju")
    #while loop control mechanism
        if (sys_params['time']):
            time.sleep(float(sys_params['repeat']))
        elif (not sys_params['infinite']):
            sys_params['repeat'] = sys_params['repeat']-1
        else:
            pass
        output=""
        NetDeviceFunc.site_devices.clear()
        #NetDeviceFunc.clear_output()    

"""  
    #progress bar initialization
    if (SHOULD_PROGRESS):
        NetDeviceFunc.progress_bar(host_file_name, command_file_name, custom_DIV)

    # Main loop        
    while ((SHOULD_TIME or SHOULD_INFINITE) or repeat):            
        # If there is only one device to run command(s)
        if option['Device']==1:
            # for one device presume cisco IOS type of device
            hostline=host_ip+custom_DIV+user_device_type+custom_DIV
            # getting device class object
            curr_device=prepare_device(hostline, dev_user, dev_pass)
            net_device = Netmiko(**curr_device)
            NetDeviceFunc.site_devices[curr_device['host']]={} 
            NetDeviceFunc.site_devices[curr_device['host']]['RAW']=[]
            NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']=[]
            # If there is only one command to execute
            if option['Command']==1:                
                # executes single command and stores it in output
                output = net_device.send_command_timing(cmd)
                #print (NetDeviceFunc.output)                               
                NetDeviceFunc.site_devices[curr_device['host']]['RAW'].append(output)
                if (SHOULD_PARSE): 
                    NetDeviceFunc.parse_output(curr_device, query_data, template)   
                else:                                   
                    NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']=NetDeviceFunc.site_devices[curr_device['host']]['RAW']
                if (SHOULD_STAMP):
                    NetDeviceFunc.stamp_output(curr_device)
                if (not SHOULD_STORE):
                    for lines in NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']:
                        print (lines)
                else:
                    NetDeviceFunc.store_output(curr_device)
            # If there is a list of commands for device to execute
            elif option['Command']==0:        
                with open(command_file_name, 'r') as cmdfile:
                    # Populating command list per device                        
                    cmdline=cmdfile.readline()
                    #print(cmdline)
                    cmdlineseq=cmdline.split(custom_DIV)  
                    # Geting command output                                          
                    for cmds in cmdlineseq[:len(cmdlineseq)-1]:                              
                    #hostoutputfile.write(net_device.send_command_timing(cmds))
                        output = output+os.linesep+net_device.send_command_timing(cmds)
                        #print (output)                                                    
                        if (SHOULD_PROGRESS):
                            NetDeviceFunc.progress_bar()      
                    #print("OUTPUT=",output)            
                    NetDeviceFunc.site_devices[curr_device['host']]['RAW'].append(output)  
                    if (SHOULD_PARSE):
                        NetDeviceFunc.parse_output(curr_device, query_data, template)
                    else:                                   
                        NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']=NetDeviceFunc.site_devices[curr_device['host']]['RAW']
                    if (SHOULD_STAMP):
                        NetDeviceFunc.stamp_output(curr_device)
                    if (not SHOULD_STORE):
                        for lines in NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']:
                            print (lines)
                    else:
                        NetDeviceFunc.store_output(curr_device)
                    #print ("+",curr_device['host'],"=",cmds)
                #print (site_devices)     
            else:
                sys.exit(1)
            net_device.disconnect()
        # If there is a list of devices to run command(s)
        elif option['Device']==0:
            with open(host_file_name, 'r') as hostfile:
                for hostline in hostfile:
                    curr_device=prepare_device(hostline,dev_user,dev_pass)
                    net_device = Netmiko(**curr_device)
                    NetDeviceFunc.site_devices[curr_device['host']]={} 
                    NetDeviceFunc.site_devices[curr_device['host']]['RAW']=[]
                    NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']=[]
                    # If there is only one command to execute
                    if option['Command']==1:
                        # executes command
                        output = net_device.send_command_timing(cmds)
                        #print (NetDeviceFunc.output)                               
                        NetDeviceFunc.site_devices[curr_device['host']]['RAW'].append(output)
                        if (SHOULD_PARSE): 
                            NetDeviceFunc.parse_output(curr_device, query_data, template)   
                        else:                                   
                            NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']=NetDeviceFunc.site_devices[curr_device['host']]['RAW']
                        if (SHOULD_STAMP):
                            NetDeviceFunc.stamp_output(curr_device)
                        if (not SHOULD_STORE):
                            for lines in NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']:
                                print (lines)
                        else:
                            NetDeviceFunc.store_output(curr_device)
                    # If there is a list of commands for devices to execute
                    elif option['Command']==0:
                        # Populating command list per device                        
                        cmdline=cmdfile.readline()
                        #print(cmdline)
                        cmdlineseq=cmdline.split(custom_DIV)  
                        # Geting command output                      
                        for cmds in cmdlineseq[:len(cmdlineseq)-1]:                              
                            #hostoutputfile.write(net_device.send_command_timing(cmds))
                            output = output+os.linesep+net_device.send_command_timing(cmds)
                            #print (output)                                                    
                            if (SHOULD_PROGRESS):
                                NetDeviceFunc.progress_bar()                  
                        NetDeviceFunc.site_devices[curr_device['host']]['RAW'].append(output)  
                        if (SHOULD_PARSE):
                            NetDeviceFunc.parse_output(curr_device, query_data, template)
                        else:                                   
                            NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']=NetDeviceFunc.site_devices[curr_device['host']]['RAW']
                        if (SHOULD_STAMP):
                            NetDeviceFunc.stamp_output(curr_device)
                        if (not SHOULD_STORE):
                            for lines in NetDeviceFunc.site_devices[curr_device['host']]['FORMAT']:
                                print (lines)
                        else:
                            NetDeviceFunc.store_output(curr_device)
                            #print ("+",curr_device['host'],"=",cmds)
                        #print (site_devices) 
                    else:
                        sys.exit(1)        
                    net_device.disconnect()    
        #while loop control mechanism
        if (SHOULD_TIME):
            time.sleep(float(repeat))
        elif (not SHOULD_INFINITE):
            repeat-=1
        else:
            pass
        output=""
        NetDeviceFunc.site_devices.clear()
        #NetDeviceFunc.clear_output()
      
"""
if __name__ == "__main__":
    main(sys.argv[1:])
