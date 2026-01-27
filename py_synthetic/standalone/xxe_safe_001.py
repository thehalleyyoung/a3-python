"""XXE: SAFE - Using defusedxml"""

def parse_xml_safe(xml_string):
    """SAFE: Uses defusedxml which prevents XXE"""
    import defusedxml.ElementTree as ET
    root = ET.fromstring(xml_string)  # SAFE: XXE protections enabled
    return root.tag

if __name__ == '__main__':
    import sys
    print(parse_xml_safe(sys.argv[1]))
