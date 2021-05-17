import sys
import time

counter=0
total_ops=1
site_devices={}     #dictonary with device IP's as keys
output=""           #single device, single command string output
custom_SEP=';'      #output csv customizable separator

# progress bar simulation function
def progress_bar(total_ops, count_ops):
    #global counter
    #global total_ops

    signs=['|','/','-','\\']
    print("\r",signs[count_ops%4],"  {0:6.2f}%".format((count_ops/total_ops)*100), end='')

# customized command output parsing function
def parse_output(curr_device, query_data, template="switch"):
    global site_devices
   
    #print (site_devices[curr_device['host']]['RAW'])
    #print (site_devices[curr_device['host']]['FORMAT'])
    if (template == "grep"):
        for raw_outputs in site_devices[curr_device['host']]['RAW']:
            for raw_lines in raw_outputs.splitlines():
                if (query_data in raw_lines):
                    site_devices[curr_device['host']]['FORMAT'].append(raw_lines)
    elif (template=="switch"):
        raise NotImplementedError            
    elif (template=="router"):
        raise NotImplementedError
    else:
        raise NameError    

# function that stores complete command output
def store_output(curr_device):
    output_filename=curr_device["hostname"]+".out"
    #output_csv_filename=curr_device['host']+".out"     
    with open(output_filename, 'a') as hostoutputfile:
        if ('STAMP' in site_devices[curr_device['host']]):
            hostoutputfile.write(site_devices[curr_device['host']]['STAMP'])
            hostoutputfile.write('\n')
        for format_lines in site_devices[curr_device['host']]['FORMAT']:
            hostoutputfile.write(format_lines)
        hostoutputfile.write('\n')

#function that adds timestamp to command output
def stamp_output(curr_device):   
    site_devices[curr_device['host']]['STAMP']=time.asctime()

#function that clears output content from previous command(s) run
def clear_output():
    global output, site_devices
    output=""
    #for devices in site_devices:
    #    if (type(site_devices[devices]) is dict):
    #        site_devices[devices].clear()
    site_devices.clear()
