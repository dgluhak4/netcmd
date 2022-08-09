#!/usr/bin/python3
"""
Script connects to Cisco devices, gets some commands output and parses output or repeats commands if needed

Usage: netcmd.py [-d|-l] <device(s)> [-c|-x] <command(s)> [-j] <device+commands> [OPTIONs]
COMMANDS:
-h --help Help screen
-g --debug Additional debug info
-d --device IP of the device OR -l --device_file_list file with the list of devices (mandatory)
-c --command single command to execute OR -x --cmd_file_list file with the list of commands per device (mandatory)
-j --json json formated file with list of devices and respected commands (one file for both device and command is used)

OPTIONS:
-r --repeat invoke repeat-based or time-based re-issuing of single command or list of commands (default is 1/once, 0 for infinite, XXs for every XX seconds)
-p --parse choose to parse output using textfsm (default is not to parse)
-t --template choose to present output date defined in custom template (default is without template, all data is displayed or stored)
-q --query a string to search for in command(s) outputs (mandatory if template is \"grep\")
-b --bar choose to use progress bar while waiting for outputs (invalid when using -d and -c options)
-y --device_type choose device type (defines who expect module processes outputs from the device)
-o --overwrite overwrite in-file provided username and password with the one taken from user input
-s --store choose if want to write command output to a file/files
-a --pass skip connecting to devices and collecting output, just store device list on media
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
from netmiko.exceptions import NetMikoTimeoutException
from netmiko.exceptions import NetMikoAuthenticationException

# loading logging and preparing to log
import logging

# GLOBALS
HELP="Usage: netcmd.py [-d|-l] <device(s)> [-c|-x] <command(s)> [-j] <device+commands> [OPTIONs] \r\n\r\n \
COMMANDS:\r\n\r\n \
-h --help Help screen\r\n\r\n \
-g --debug Additional debug info\r\n\r\n \
-d --device IP of the device OR -l --device_file_list file with the list of devices (mandatory)\r\n \
-c --command single command to execute OR -x --cmd_file_list file with the list of commands per device (mandatory)\r\n \
-j --json json formated file with list of devices and respected commands (one file for both device and command is used)\r\n\r\n \
OPTIONS:\r\n\r\n \
-r --repeat invoke repeat-based or time-based re-issuing of single command or list of commands (default is 1/once, 0 for infinite, XXs for every XX seconds)\r\n \
-p --parse choose to parse output using textfsm (default is not to parse)\r\n \
-t --template choose to present output date defined in custom template (default is without template, all data is displayed or stored)\r\n \
-q --query a string to search for in command(s) outputs (mandatory if template is \"grep\")\r\n \
-b --bar choose to use progress bar while waiting for outputs (invalid when using -d and -c options)\r\n \
-y --device_type choose device type (defines who expect module processes outputs from the device)\r\n \
-o --overwrite overwrite in-file provided username and password with the one taken from user input\r\n \
-s --store choose if want to write command output to a file/files\r\n \
-a --pass skip connecting to devices and collecting output, just store device list on media\r\n"

# program exit function (with error message)
def exit_error(err_message="Unknown error"):
    """
    Exit function expanded with detail error message.

    Input: Error message
    """
    print(err_message)
    print(HELP)
    sys.exit(2)

# error message function
def continue_error(err_message="Unknown error"):
    """
    Error function with detail error message. Continues code execution.

    Input: Error message
    """
    print (err_message)
    print ("Continuing with execution!")
    return

# progress bar simulation function
def progress_bar(total_ops, count_ops):        

    signs=['|','/','-','\\']
    print("\r",signs[count_ops%4],"  {0:6.2f}%".format((count_ops/total_ops)*100), end='')


# populating device list and options
def prepare_device_data(cmd_options):
    """
    Function does formating of input data, such as device list and device command list files, commands and options
    The output is populated dictionary with devices parameters and device commands
    """

    SHOULD_PARSE = False #when True parsing to dictonary, default is not to parse
    SHOULD_PROGRESS = False #when True display progress bar while executing multiple comamands on multiple devices, default is not to display progress bar
    SHOULD_STORE = False #when True should write command output to a file named after host, default is to not store the output          
    SHOULD_TIME = False #when True repeat value means timing in seconds between repetion of command execution
    SHOULD_INFINITE = False #indicating that process of executing command(s) on device(s) is repeating indefinetly
    SHOULD_OVERWRITE = False #indicating that in-file provided username and password has to be overwritten by the user input values
    custom_DIV='%'
    default_TYPE="cisco_ios"
    default_MODEL="custom" 
    SHOULD_DEBUG = False  #indicating that invoke should provide additional debug info about various variable values
    SHOULD_PASS = False #indicating whether to pass at least once through the connection data, used for data format conversion

    dev_params={"host_file_name":"","command_file_name":"","host_ip":"127.0.0.1","cmd":"","overwrite":SHOULD_OVERWRITE, \
        "user_device_type":default_TYPE,"invalid_option":{'Device':0,'Command':0},"option":{"Device":2,"Command":2}}
    sys_params={"repeat":1,"progress":SHOULD_PROGRESS,"time_start":time.asctime(),"timestamps":[],"total_ops":0, \
        "time": SHOULD_TIME, "store": SHOULD_STORE, "parse": SHOULD_PARSE, "datamodel":default_MODEL, "query_data":"", \
        "template":"none", "infinite": False, "divisor": custom_DIV, "debug": SHOULD_DEBUG, "pass": SHOULD_PASS}
    dev_list={}

    # analysis and prepraration of input arguments
    for curr_opts, curr_vals in cmd_options:
        if curr_opts in ("-h", "--help"):
            print(HELP)
            sys.exit(0)
        elif curr_opts in ("-g","--debug"):
            sys_params["debug"] = True
        elif curr_opts in ("-p","--parse"):   
            exit_error("Feature not implemented yet")         
            #sys_params["parse"] = True
        elif curr_opts in ("-b","--bar"):            
            sys_params["progress"] = True
        elif curr_opts in ("-s","--store"):            
            sys_params["store"] = True
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
                        sys_params["repeat"] = 65535
                        sys_params['infinite'] = True
                else:
                    exit_error("Invalid repetion request")
        elif curr_opts in ("-t","--template"):         
            exit_error("Feature not implemented yet")
            #sys_params["parse"] = True
            #sys_params["template"]=curr_vals
        elif curr_opts in ("-q","--query"):
            exit_error("Feature not implemented yet")
            #sys_params["query_data"]=curr_vals
        elif curr_opts in ("-o","--overwrite"):
            dev_params["overwrite"] = True
        elif curr_opts in ("-i","--insert"):            
            dev_params["insert"] = True
        elif curr_opts in ("-j","--json"):
            sys_params["datamodel"]="json"
            dev_params["host_file_name"]=curr_vals
            dev_params["invalid_option"]['Command'] +=1
            dev_params["invalid_option"]['Device'] +=1            
            dev_params["option"]['Device']=3
            dev_params["option"]['Command']=3
            try:
                hostfile=open(dev_params['host_file_name'],'r')
            except FileNotFoundError as err:
                exit_error(err)
        elif curr_opts in ("-a","--pass"):
            sys_params['pass'] = True
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
    if dev_params["option"]['Device']*dev_params["option"]['Command'] == 1:                
        sys_params['progress'] = False
    else:
        sys_params['total_ops']*=sys_params['repeat']

    # provjera analize input argumenata
    if (sys_params["debug"]):
        print("\nPripremljeni device i system podaci (f(prepare_device_data))")
        print (dev_params)
        print (sys_params)
    # Getting username and password of user connecting to devices 
    dev_user = input("Input user name used to collect information from devices: ")    
    dev_pass = getpass()
    # popunjavanje liste uredjaja
    cmdlineseq=[] 
    # ako je samo jedan uredjaj iz prompta
    if (dev_params["option"]['Device']) == 1:
        hostline=dev_params['host_ip']+sys_params["divisor"]+dev_params['user_device_type']+sys_params["divisor"]+"SINGLE_DEVICE"
        new_device=prepare_device(hostline,dev_user,dev_pass, sys_params["divisor"], dev_params["overwrite"], sys_params["debug"])        
        if (dev_params["option"]['Command']) == 1:
            new_device['commands'].append(dev_params['cmd'])
            sys_params['total_ops']=1
        elif (dev_params["option"]['Command']) == 2:            
            # Populating command list for one device
            cmdline=cmdfile.readline()
            if (sys_params["debug"]):
                print("\nPrepare data - commands (f(prepare_device_data))")
                print(cmdline)
            cmdlineseq=cmdline.split(sys_params["divisor"])
            sys_params['total_ops']+=len(cmdlineseq)
            new_device['commands']=cmdlineseq.copy()
            cmdfile.close()
        else:
            exit_error("JSON model not allowed in single device input parameter!")
        #dev_list.append(new_device)
        dev_list.update(new_device)
    elif (dev_params["option"]['Device']) == 2:            
        if (dev_params["option"]['Command']) == 3:
            exit_error("JSON model not allowed in single device input parameter!")
        else:    
            for hostline in hostfile:                
                cmdlineseq.clear()
                new_device=prepare_device(hostline,dev_user,dev_pass, sys_params["divisor"], dev_params["overwrite"], sys_params["debug"])
                # Populating command list for current device
                if (dev_params["option"]['Command']) == 2: 
                    cmdline=cmdfile.readline()     
                    if (sys_params["debug"]):
                        print("\nIspis pojedine komande prilikom pripreme liste (f(prepare_device_data))")
                        print(cmdline)
                    cmdlineseq=cmdline.split(sys_params["divisor"])
                    sys_params['total_ops']+=len(cmdlineseq)
                else:
                    cmdlineseq.append(dev_params['cmd'])
                    sys_params['total_ops']+=len(cmdlineseq)
                new_device['commands']=cmdlineseq.copy()
                dev_list.append(new_device)      

            if (dev_params["option"]['Command']) == 2:   
                cmdfile.close()                        
        hostfile.close()
    elif (dev_params["option"]['Device']) == 3:
        # OPEN JSON FILE AND DO SOMETHING
        dev_list=json.load(hostfile)
        if (sys_params["debug"]):
            print("\nLoaded JSON data (f(prepare_device_data))")
            print (dev_list)
        for dev in dev_list:
            if (sys_params["debug"]):
                print("\nCurrent key value from JSON data (f(prepare_device_data))")
                print (dev)
            if "host" in dev_list[dev]["device"].keys():
                if "username" in dev_list[dev]["device"].keys():
                    if (len(dev_list[dev]["device"]["username"]) == 0) or dev_params['overwrite']:
                        dev_list[dev]["device"]["username"]=dev_user
                else:
                    dev_list[dev]["device"]["username"]=dev_user
                if "password" in dev_list[dev]["device"].keys():
                    if (len(dev_list[dev]["device"]["password"]) == 0) or dev_params['overwrite']:
                        dev_list[dev]["device"]["password"]=dev_pass
                else:
                    dev_list[dev]["device"]["password"]=dev_pass
                if "secret" in dev_list[dev]["device"].keys():
                    if (len(dev_list[dev]["device"]["secret"]) == 0) or dev_params['overwrite']:
                        dev_list[dev]["device"]["secret"]=dev_pass
                else:
                    dev_list[dev]["device"]["secret"]=dev_pass                    
                if "hostname" in dev_list[dev].keys():
                    if (len(dev_list[dev]["hostname"]) == 0):
                        dev_list[dev]["hostname"]=dev
                else:
                    dev_list[dev]["hostname"]=dev
                dev_list[dev]["output"]={}
                sys_params['total_ops']+=len(dev_list[dev]['commands'])
            else:                
                continue_error("{} device is missing mandatory host value...skiping".format(dev_list[dev]["hostname"]))
                del dev_list[dev]
        if (sys_params["debug"]):
            print("\nJSON data prepared as device list (f(prepare_device_data))")
            print (dev_list)
    else:
        exit_error("Invalid reference to device list!")

    return sys_params, dev_list

# Populating device with device properties
def prepare_device(hostline,dev_user,dev_pass, custom_DIV, overwrite, debug = False):
    """
    Function prepares all data need for successful connection to remote device.
    Minimal data needed: device IP, device type, device name, device username, username password.
    """
    
    hostlineseq=hostline.split(custom_DIV)    
    hostlineseq.pop()   
    # host data preparation
    if (len(hostlineseq) == 3):
        hostlineseq.append(dev_user)
        hostlineseq.append(dev_pass)
    elif (len(hostlineseq) == 5 and overwrite):
        hostlineseq.pop()   
        hostlineseq.pop()   
        hostlineseq.append(dev_user)
        hostlineseq.append(dev_pass)
    else:
        pass
    if (debug):
        print (len(hostlineseq))
        print (len(hostline))
        print (hostlineseq)
        print (hostline)
    # host data application to host class structure
    netmiko_device = {
        'host': hostlineseq[0],
        #'device_type': 'cisco_ios'
        'device_type': hostlineseq[1][:len(hostline)-2],        
        #'username': dev_user,
        #'password': dev_pass,        
        'username': hostlineseq[3],
        'password': hostlineseq[4],
        'secret': hostlineseq[4]
        #'global_delay_factor': 2
    }
    if (netmiko_device['device_type'] == 'juniper'):
        netmiko_device['global_delay_factor'] = 2    
    new_device = {
        hostlineseq[2]: {
            'device':netmiko_device,
            'hostname': hostlineseq[2],
            'commands':[],
            'output':[]
        }
    }
    return new_device

# function that stores complete command output per device by appending the output file
# this allows storing many iterations per device
def store_output(curr_device,sys_params):
    output_filename=curr_device["hostname"]+".out"
    #output_csv_filename=curr_device['host']+".out"     
    hostoutputfile.write(curr_device["hostname"])
    with open(output_filename, 'a') as hostoutputfile:
        for single_item in curr_device["output"]:
            if (sys_params["debug"]):
                print("\nIspis snimljenih podataka (f(store_output))")
                print(curr_device["output"][single_item], "\r\n", curr_device["output"][single_item]["timestamp"], "\r\n", curr_device["output"][single_item]["output"])
            hostoutputfile.write(curr_device["output"][single_item]) 
            hostoutputfile.write(curr_device["output"][single_item]["output"]) 


# function that prints current "operations done" statistics
def stats_output(citer,count_ops,sys_params,if_iter = False):

    signs=['|','/','-','\\']
    if if_iter:
        print("#Iteration: {}, at: {}".format(citer,time.ctime(sys_params['timestamps'][citer])))
        print("#Operations: {}/{}, time took: {:.4f}".format(count_ops,sys_params['total_ops']*sys_params['repeat'],sys_params['timestamps'][citer]-sys_params['timestamps'][citer-1]))
    else:        
        print("\r",signs[count_ops%4],"  {0:6.2f}%".format((count_ops/sys_params['total_ops'])*100), end='')

# core function    
def main(argumentList):
    """
Main function that deploys list of commands to a list of devices and prints/parses/stores its output
    """
    # global SHOULD_PARSE, SHOULD_PROGRESS, SHOULD_STORE, SHOULD_TIME, SHOULD_INFINITE
    try:
        cmd_options, cmd_values = getopt.getopt(argumentList, "hgapbsoj:d:l:c:x:r:t:q:y:", ["help","debug","pass","parse","bar","store","overwrite",\
            "json=","device_list=","device=","device_file_list=","command=","cmd_file_list=","repeat=","template=","query=","device_type="])
    except getopt.GetoptError:
        exit_error("Invalid input option!")
    logging.basicConfig(filename='test.log', level=logging.DEBUG)
    logger = logging.getLogger("netmiko")
    sys_params={}
    device_template={}  
    device_list={}
    sys_params, device_list = prepare_device_data(cmd_options)
    if (sys_params["debug"]):
        print("\nProvjera ucitanih sistemskih i device podataka (f(main))")
        print(sys_params)
        print(device_list)

    # Main loop       
    iter=sys_params['repeat'] #iter=number of expected iterations
    citer=0 #citer=current iteration
    sys_params['timestamps'].append(time.time())
    count_ops=0 #count_ops=current number of operation done (operation=command/device)
    while (((sys_params['time'] or sys_params['infinite']) or iter) and not sys_params['pass']):    
        #count_ops=0 #count_ops=current number of operation done (operation=command/device)
        citer+=1        
        for device in device_list:
            if (sys_params["debug"]):
                print("\nIspis pojedinog devicea prilikom obrade (f(main))")
                print(device)                
            else:
                #curr_device=device["device"]               
                #net_device = Netmiko(**curr_device)
                pass
            try:
                net_device = Netmiko(**device_list[device]["device"])                                    
                for cmd in device_list[device]['commands']:
                    #output=""
                    count_ops+=1  
                    device_list[device]["output"][cmd]={"timestamp","output"}
                    device_list[device]["output"][cmd]["timestamp"]=time.asctime()
                    device_list[device]["output"][cmd]["output"]=net_device.send_command_timing(cmd)
                    if (sys_params['progress'] and sys_params['store']):
                        #print (sys_params['total_ops'], count_ops)
                        stats_output(citer,count_ops,sys_params)
                    else:
                        print (device_list[device]["output"][cmd]["output"])
                    #device_list[device]["output"].append(output)            
                if sys_params['store']:
                    print("Sada snimam iteraciju")
                    store_output(device_list[device],sys_params)
                    #print(device["output"])
                device_list[device]["output"].clear()       
            except NetMikoAuthenticationException:
                continue_error("Username/password error or reachability error. Skiping device {}, going to next.".format(device_list[device]['device']['host']))   
            except NetMikoTimeoutException:
                continue_error("TCP Connection to device {} failed".format(device_list[device]['device']['host']))       
            except:
                continue_error("Neka nepoznata greska u komunikaciji s {}".format(device_list[device]['device']['host']))          
        sys_params['timestamps'].append(time.time())
        stats_output(citer,count_ops,sys_params,True)
    #while loop control mechanism
        if (sys_params['time']):
            time.sleep(float(sys_params['repeat']))
            #count_ops=0
        elif (not sys_params['infinite']):
            iter = iter-1
        else:
            pass
    if (sys_params['pass']):
        print("\nPripremljena lista uredjaja:")
        print(device_list)

if __name__ == "__main__":
    main(sys.argv[1:])
