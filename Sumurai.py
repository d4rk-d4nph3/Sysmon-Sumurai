import csv
import xml.etree.ElementTree as ET
from datetime import datetime

SYSMON_XML_CONFIG = 'sys.xml' # Default Config File


def check_sysmon_schema(xml_root):
    if xml_root.tag == 'Sysmon':
        schema_version = xml_root.attrib.get('schemaversion')
        print("The Sysmon config schema's version is {}".format(
                                                        schema_version), '\n')
    else:
        print("Config file is not of Sysmon!")
        print("Exiting...")
        exit()

def check_config_entries():
    if hash_tag is not None:
        print("Activated Hash Algorithms are {}".format(hash_tag.text), '\n')
    else:
        print("Activated Hash Algorithms are not configured and will be auto-set to the default value", '\n')

    if archive_tag is not None:
        print('Archive folder has been configured to {}'.format(archive_tag.text), '\n')
    else:
        print('Archive folder has not been configured and will be auto-set to the default value', '\n')

    if revoc_tag is not None:
        print("Driver Signature Revocation is enabled [+]", '\n')
    else:
        print("Driver Signature Revocation is not enabled [-]", '\n')


def parse_config_entries(xml_root):
    global hash_tag, revoc_tag, archive_tag, event_tag

    try:
        if tags.index('HashAlgorithms') != -1:
            hash_tag = xml_root[tags.index('HashAlgorithms')]
    except ValueError:
        pass

    try:
        if tags.index('CheckRevocation') != -1:
            revoc_tag = xml_root[tags.index('CheckRevocation')]
    except ValueError:
        pass

    try:
        if tags.index('ArchiveDirectory') != -1:
            archive_tag = xml_root[tags.index('ArchiveDirectory')]
    except ValueError:
        pass

    try:
        if tags.index('EventFiltering') != -1:
            event_tag = xml_root[tags.index('EventFiltering')]
    except ValueError:
        pass

def parse_without_rule_group(rule_group):
    print('Event:  ' + rule_group.tag)
    print('<------ ' + rule_group.tag + '  On Match: ' 
                     + rule_group.attrib.get('onmatch') + ' ------>')
    for each_rule in rule_group:
        if each_rule.attrib.get('name') is None:
                            print(each_rule.tag + '  ' 
                     + each_rule.attrib.get('condition') + ' --> ' 
                     + each_rule.text)
        else:
            print('Rule Name: ' + each_rule.attrib.get('name') 
                     + '  ' + each_rule.tag + '  ' 
                     + each_rule.attrib.get('condition') + ' --> ' 
                     + each_rule.text)    

def parse_with_rule_group(each_sysmon_event):
    print('<------ ' + each_sysmon_event.tag + '  On Match: ' 
                     + each_sysmon_event.attrib.get('onmatch') + ' ------>')

    for each_rule in each_sysmon_event:
        if each_rule.tag == 'Rule':
            if each_rule.attrib.get('groupRelation') == 'and':
                print('<== AND Grouping of Rules ==>')
                for each in each_rule:
                    print(each.tag, each.attrib.get('condition'), each.text)
            elif each_rule.attrib.get('groupRelation') == 'or':
                print('<== OR Grouping of Rules ==>')
                for each in each_rule:
                    print(each.tag, each.attrib.get('condition'), each.text)
            print('\n')
        elif each_rule.attrib.get('name') is None:
            print(each_rule.tag + '  ' 
                                + each_rule.attrib.get('condition') + ' --> ' 
                                + each_rule.text)
        else:
            print('RuleName: ' + each_rule.attrib.get('name') 
                               + '  ' + each_rule.tag + '  ' 
                               + each_rule.attrib.get('condition') + ' --> ' 
                               + each_rule.text)

def event_filter(event_tag):
    print('Event Filtering Section -------->', '\n')
    for rule_group in event_tag:
        if rule_group.tag != 'RuleGroup':
            parse_without_rule_group(rule_group)
        else:
            for each_sysmon_event in rule_group:
                print('Event:  ' + each_sysmon_event.tag)
                
                if len(each_sysmon_event) == 0:
                    print(each_sysmon_event.tag 
                            + ' has no filtering rules configured')

                    if each_sysmon_event.attrib.get('onmatch') == 'include':
                        print('No events are logged for ' 
                            + each_sysmon_event.tag)
                    else:
                        print('All events are logged for ' 
                            + each_sysmon_event.tag)
                else:
                    parse_with_rule_group(each_sysmon_event)
                print('-' * 150, '\n') 


try:
    xml_tree = ET.parse(SYSMON_XML_CONFIG)
    xml_root = xml_tree.getroot()
except FileNotFoundError:
    print("The Sysmon config file does not exist!!")
    print("Exiting...")
    exit()

print('Report created on {}'.format(datetime.now()), '\n')
check_sysmon_schema(xml_root)

tags = []
hash_tag = None
revoc_tag = None
archive_tag = None
event_tag = None

for each in xml_root:
    tags.append(each.tag)

parse_config_entries(xml_root)
check_config_entries()
event_filter(event_tag)

