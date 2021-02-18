#! /usr/bin/python
import os
import sys
import paramiko
import ConfigParser
import logging
import time
import argparse
import ipaddr
import requests
import json
import random

# Setup the common config files
# Setup relative path
cfg_file = os.path.join(os.path.dirname(__file__), '../../config/setup_config.cfg')
# Import config file
config = ConfigParser.ConfigParser()
config.read(cfg_file)
# Modules directory
sys.path.append(config.get("default", "test_root") + "/" + "modules")

script_cfg_file = os.path.join(os.path.dirname(__file__), '../../config/nbs/nbs_subscription.cfg')
script_cfg = ConfigParser.ConfigParser()
script_cfg.read(script_cfg_file)

from Logging_Framework import Logging_Framework
from massrc.com.citrix.mas.nitro.service.nitro_service import nitro_service
from massrc.com.citrix.mas.nitro.service.options import options
from massrc.com.citrix.mas.nitro.exception.nitro_exception import nitro_exception
from massrc.com.citrix.mas.nitro.resource.config.mps.config_job import config_job
from massrc.com.citrix.mas.nitro.resource.config.mps.configuration_template import configuration_template
from massrc.com.citrix.mas.nitro.resource.config.mps.config_command import config_command
from massrc.com.citrix.mas.nitro.resource.config.mps.config_variable import config_variable
from massrc.com.citrix.mas.nitro.exception.nitro_exception import nitro_exception
from massrc.com.citrix.mas.nitro.resource.config.mps.device_group import device_group
import helperFuncs as helperFuncs
import device_operations
import config_mgmt_operations
from MAS_Communicator import MAS_Communicator


def get_mas_client(mas_details, logger_object):
    try:
        ip = mas_details['ip']
        username = mas_details.get('username')
        password = mas_details.get('password')
        protocol = mas_details.get('protocol', 'https')
        mas_client = nitro_service(ip, protocol)
        mas_client.login(username, password, 120)
        return mas_client
    except nitro_exception as e:
        logger_object.critical("--------------")
        logger_object.critical("Exception :")
        logger_object.critical("--------------")
        logger_object.critical("ErrorCode : " + str(e.errorcode))
        logger_object.critical("Message : " + e.message)
        logger_object.critical("Oops! Unable to log into the MAS.")
        return False
    except Exception as e:
        helperFuncs.print_exception_details(logger_object)
        return False


def get_session_id(mas_ip, mas_username, mas_password, is_Cloud):
    try:
        mas_ip = mas_ip
        username = mas_username
        password = mas_password
        isCloud = is_Cloud
        if isCloud == 'false':
            nitro_call = "https://" + mas_ip + "/nitro/v1/config/login"
            headers = {'content-type': "application/json", 'isCloud': 'true'}
            payload = 'object={"login":{"ID":"' + username + '","Secret":"' + password + '"}}'
        else:
            nitro_call = "https://" + mas_ip + "/nitro/v1/config/login"
            headers = {'content-type': "application/json"}
            payload = 'object={"login":{"ID":"' + username + '","Secret":"' + password + '"}}'
        response = requests.request("POST", nitro_call, data=payload, headers=headers)
        sessionid = response.json().get('login')[0]['sessionid']
        return sessionid
        
    except Exception as e:
        logger_object.critical("Oops! Unable to log into the MAS.")
        

if __name__ == '__main__':
    try:
        # parse the command line Arguments
        parser = argparse.ArgumentParser()
        parser.add_argument('--log_folder', help="Log Folder", action="store", dest="log_folder")
        parser.add_argument('--result_file', help="Result File", action="store", dest="result_file")
        parser.add_argument('-c', '--config_file', help="Config File", default='')
        args = parser.parse_args(sys.argv[1:])
        if args.config_file != '':
            script_cfg_file = args.config_file
            script_cfg = ConfigParser.ConfigParser()
            script_cfg.read(script_cfg_file)
        if not args.log_folder or not args.result_file:
            print "Error! Log folder or Result File has not been provided!"
            exit()
        log_folder = args.log_folder
        result_file = args.result_file
        result_path = log_folder + "/" + result_file
        script_path = sys.argv[0]
        script_name = script_path.split("/")[-1].split(".")[0]
        script_log = script_name + ".log"

        # Setup logging framework
        loglevel = script_cfg.get("default", "loglevel")
        log_framework_object = Logging_Framework()
        log_folder = log_framework_object.setup_log_files(log_folder=log_folder, logfile=script_log, loglevel=loglevel)
        logger_object = log_framework_object.setup_log(script_name + ".main")

        logger_object.info("Beginning of Script: " + script_path)
        helperFuncs.print_setup_details(log_framework_object, script_cfg)

        #################################################################################
        #####                        INSERT YOUR CODE HERE                      #########
        #################################################################################

        tcid_258 = "111.49.1.258"
        tcid_259 = "111.49.1.259"
        tcid_260 = "111.49.1.260"
        tcid_261 = "111.49.1.261"
        tcid_262 = "111.49.1.262"

        result_set = dict()
        result_set[tcid_258] = dict()
        result_set[tcid_259] = dict()
        result_set[tcid_260] = dict()
        result_set[tcid_261] = dict()
        result_set[tcid_262] = dict()


        logger_object.info("#############################################################")
        logger_object.info("This script has the following test cases:")
        logger_object.info(tcid_258 + ": Verify adding a new subscription")
        logger_object.info(tcid_259 + ": Verify the new added subscription is in list of subscriptions")
        logger_object.info(tcid_260 + ": Verify updating a subscription")
        logger_object.info(tcid_261 + ": Verify getting an available subscription by id")
        logger_object.info(tcid_262 + ": Verify deleting a subscription")

        logger_object.info("#############################################################")

        mas_ip = script_cfg.get("mas_1", "ip")
        mas_username = script_cfg.get("mas_1", "username")
        mas_password = script_cfg.get("mas_1", "password")
        is_Cloud = script_cfg.get("mas_1", "isCloud")


        mas_details = dict()
        mas_details['ip'] = mas_ip
        mas_details['username'] = mas_username
        mas_details['password'] = mas_password

        logger_object.info("MAS IP: " + mas_ip)
        logger_object.debug("mas_details: " + str(mas_details))



        '''
                        ########## TEST CASE FOR DELETE DEVICE WHICH IS BEING USED IN NEXT CASES AS A 1ST CLEANUP#########
                        try:
                                device1_deleted = device_operations.delete_device_from_mas(mas_details, device_details1, log_framework_object)
                                #device2_deleted = device_operations.delete_device_from_mas(mas_details, device_details2, log_framework_object)
                                #if device1_deleted == True and device2_deleted == True:
                                if device1_deleted == True:
                                        logger_object.critical("-------Devices are deleted from MAS - As expected.")
                        except nitro_exception as e:
                                logger_object.critical("--------------")
                                logger_object.critical("Exception :")
                                logger_object.critical("--------------")
                                logger_object.critical("ErrorCode : "+ str(e.errorcode))
                                logger_object.critical("Message : " + e.message)

                        ########## TEST CASE FOR ADDING ADC TO ADM #########

                        try:
                                device1_added = device_operations.add_device_to_mas(mas_details, device_details1, log_framework_object, agent_details)
                if device1_added == True:
                logger_object.critical("------- Test Case 264 Passed: Device added to MAS - As expected.")
                result_set[tcid_264]['result'] = True
                else:
                logger_object.critical("------- Test Case 264 Failed: Device not added to MAS - Not expected.")
                result_set[tcid_264]['result'] = False

                        except nitro_exception as e:
                                logger_object.critical("--------------")
                                logger_object.critical("Exception :")
                                logger_object.critical("--------------")
                                logger_object.critical("ErrorCode : "+ str(e.errorcode))
                                logger_object.critical("Message : " + e.message)
                                result_set[tcid_264]['result'] = False
        '''

        ########## TEST CASES FOR NSDEVICE PROFILE DETAILS NITRO #########
        '''
                        client = nitro_service(mas_ip,"https","v1")
                        client.certverify = False
                        client.isCloud = True
                        client.set_credential(mas_username, mas_password)
                        client.timeout = 1800
                        client.login(mas_username, mas_password, 1800)
                        sessionid = "SESSID="+client.sessionid
                        isCloud = client.isCloud
                        login_token = ""
                        logger_object.info("Session ID: " + sessionid)
        '''
        # return sessionid
        SESSIONID = get_session_id(mas_ip,mas_username,mas_password,is_Cloud)
        logger_object.critical("The Session Id is : "+ SESSIONID)
        
        subscription_call = "https://"+ mas_ip +"/nbs_subscription"
        headers = {'content-type':"application/json",'mps-user': "rahul.kumar@citrix.com",'mps-tenant': "g9i80ep3uhox",'cookie':"SESSID=" +SESSIONID + ""}
        response = requests.request("GET", subscription_call, headers=headers)
        logger_object.info("subscription call response:" + str(response.json()))


        try:
            flag = False
            myobj = {'content-type': "application/json",'mps-user': "rahul.kumar@citrix.com",'mps-tenant': "g9i80ep3uhox", 'cookie': "SESSID=" + SESSIONID + ""}
            add_subscription_call = "https://" + mas_ip + "/nbs_subscription"
            json_payload = {"nbs_subscription":{"name": "TestSubscription","subscribed_by": "sugyanib", "export_frequency": "daily",
                              "subsribed_datasets": [{"category": "security", "feature": "bot"}],
                              "export_config": {"end_point": "https://upload_my_data_here.com/", "token": "my_token", "export_type": "http"}}}
            logger_object.info(str(json_payload))

            json_payload = json.dumps(json_payload)
            res = requests.request("POST", add_subscription_call, data=json_payload, headers=myobj)
            logger_object.info("response status code " + str(res.status_code))
            logger_object.info(str(res.json()))
            nbs_subscription = res.json().get('nbs_subscription')

            logger_object.info(str(nbs_subscription))
            subscription_name1 = nbs_subscription["name"]
            subscriber1 = nbs_subscription["subscribed_by"]

            subscription_id = ''
            if res.status_code == 201:
                flag = True

            if flag :
                logger_object.critical("The output of successful subscription request : " + str(res.json()))
                logger_object.critical("Test Case 258 Passed: Verify adding a new subscription - As expected")
                result_set[tcid_258]['result'] = True
            else:
                logger_object.critical("Test Case 258 Failed: Verify adding a new subscription - Not As expected")
                result_set[tcid_258]['result'] = False

            subscription_call = "https://" + mas_ip + "/nbs_subscription"
            headers = {'content-type': "application/json",'mps-user': "rahul.kumar@citrix.com",'mps-tenant': "g9i80ep3uhox",'cookie': "SESSID=" + SESSIONID + ""}
            response = requests.request("GET", subscription_call, headers=headers)
            logger_object.info("Response of subscription call" + str(response.json()))

            data_json = response.json().get('nbs_subscription')
            flag = False

            for count in data_json:

                subscription_name = count["name"]
                subscriber = count["subscribed_by"]
                get_id = count["id"]

                logger_object.info("Subscription Name : " + str(subscription_name) +" Subscriber Name : " + str(subscriber)+" Subscription Id : " + str(get_id))
                if subscription_name == subscription_name1 and subscriber == subscriber1:
                    subscription_id = get_id
                    flag = True
                else:
                    continue

            if flag :
                logger_object.critical("The new subscription id  is : " + subscription_id)
                logger_object.critical(
                    "Test Case 259 Passed: Verify the new added subscription is in list of subscriptions - As expected")
                result_set[tcid_259]['result'] = True
            else:
                logger_object.critical(
                    "Test Case 259 Failed: Verify the new added subscription is in list of subscriptions - Not As expected")
                result_set[tcid_259]['result'] = False


            flag = False
            myobj = {'content-type': "application/json",'mps-user': "rahul.kumar@citrix.com",'mps-tenant': "g9i80ep3uhox",'cookie': "SESSID=" + SESSIONID + ""}
            update_subscription_call = "https://" + mas_ip + "/nbs_subscription/"+ subscription_id
            json_payload = {"nbs_subscription":{"name": "TestSubscription","subscribed_by": "rachel", "export_frequency": "daily",
                              "subsribed_datasets": [{"category": "security", "feature": "bot"}, {"category": "security", "feature": "waf"}],
                              "export_config": {"end_point": "https://upload_my_data_here.com/", "token": "my_token1", "export_type": "http"}}}
            logger_object.info(str(json_payload))

            json_payload = json.dumps(json_payload)
            res = requests.request("PUT", update_subscription_call, data=json_payload, headers=myobj)
            logger_object.info("response status code " + str(res.status_code))
            logger_object.info(str(res.json()))

            if res.status_code == 200 :
                flag = True

            if flag :
                logger_object.critical(
                    "Test Case 260 Passed: Verfify updating a subscription - As expected")
                result_set[tcid_260]['result'] = True
            else:
                logger_object.critical(
                    "Test Case 260 Failed: Verfify updating a subscription - Not As expected")
                result_set[tcid_260]['result'] = False

            flag = False
            get_subscription_call = "https://" + mas_ip + "/nbs_subscription/"+ subscription_id
            headers = {'content-type': "application/json",'mps-user': "rahul.kumar@citrix.com",'mps-tenant': "g9i80ep3uhox", 'cookie': "SESSID=" + SESSIONID + ""}
            res = requests.request("GET", get_subscription_call, headers=headers)
            logger_object.info("response status code " + str(res.status_code))
            logger_object.info("Response of get subscription call by id" + str(res.json()))

            if res.status_code == 200 :
                flag = True

            if flag :
                logger_object.critical(
                    "Test Case 261 Passed: Verify getting an available subscription by id - As expected")
                result_set[tcid_261]['result'] = True
            else:
                logger_object.critical(
                    "Test Case 261 Failed: Verify getting an available subscription by id - Not As expected")
                result_set[tcid_261]['result'] = False

            flag = False
            delete_subscription_call = "https://" + mas_ip + "/nbs_subscription/"+ subscription_id
            headers = {'content-type': "application/json",'mps-user': "rahul.kumar@citrix.com",'mps-tenant': "g9i80ep3uhox", 'cookie': "SESSID=" + SESSIONID + ""}
            res = requests.request("DELETE", delete_subscription_call, headers=headers)
            logger_object.info("response status code " + str(res.status_code))

            if res.status_code == 204 :
                flag = True

            if flag :
                logger_object.critical(
                    "Test Case 262 Passed: Verify deleting a subscription - As expected")
                result_set[tcid_262]['result'] = True
            else:
                logger_object.critical(
                    "Test Case 262 Failed: Verify deleting a subscription - Not As expected")
                result_set[tcid_262]['result'] = False


        except nitro_exception as e:
            logger_object.critical("--------------")
            logger_object.critical("Exception :")
            logger_object.critical("ErrorCode : " + str(e.errorcode))
            logger_object.critical("Message : " + e.message)

        result_set[tcid_258]['title'] = "Verify adding a new subscription"
        result_set[tcid_259]['title'] = "Verify the new added subscription is in list of subscriptions"
        result_set[tcid_260]['title'] = "Verify updating a subscription"
        result_set[tcid_261]['title'] = "Verify getting an available subscription by id"
        result_set[tcid_262]['title'] = "Verify deleting a subscription"


    except Exception as e:
        print "Exception: " + str(e)
        logger_object.critical("Oops! Something went wrong.")
        logger_object.critical("Exception: " + str(e))
    finally:
        helperFuncs.generate_results(result_set, result_path, log_framework_object)

