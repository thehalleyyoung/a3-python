"""XXE: Unsafe XML parsing with entity expansion"""

def parse_xml(xml_string):
    """BUG: XXE - XML parsed without disabling external entities"""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_string)  # BUG: Allows XXE attacks
    return root.tag

if __name__ == '__main__':
    import sys
    print(parse_xml(sys.argv[1]))
