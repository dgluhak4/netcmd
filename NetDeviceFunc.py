import sys
import time

counter=0
total_ops=1
site_devices={}     #dictonary with device IP's as keys
output=""           #single device, single command string output
custom_SEP=';'      #output csv customizable separator

# progress bar simulation function
def progress_bar(host_file_name="",command_file_name="", custom_DIV="%"):
    global counter
    global total_ops

    signs=['|','/','-','\\']
    dim1=0
    dim2=0
    # extract dimensions of operations = devices*commands
    if counter == 0:
        if host_file_name:
            with open(host_file_name, 'r') as hostfile:
                for hostline in hostfile:
                    dim1+=1
        else:
            dim1=1
        if command_file_name:
            with open(command_file_name, 'r') as cmdfile:
                cmdlineseq=cmdfile.readline().split(custom_DIV)
                dim2=len(cmdlineseq)
        else:
            dim2=1
        #print ("DIM1=", dim1, "DIM2=", dim2)
        # calculate total length of all operations
        total_ops=dim1*dim2
    print('\r',signs[counter%4], "  {0:6.2f}%".format((counter/total_ops)*100), end='')
    counter+=1

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
    output_filename=curr_device['host']+".out"
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
