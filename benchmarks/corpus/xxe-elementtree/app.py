import xml.etree.ElementTree as ET


def parse_feed(xml_text):
    return ET.fromstring(xml_text)
