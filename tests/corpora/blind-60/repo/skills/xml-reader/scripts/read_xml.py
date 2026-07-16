import sys
from lxml import etree

parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
document = etree.parse(sys.argv[1], parser)
print(etree.tostring(document.getroot(), encoding="unicode"))
