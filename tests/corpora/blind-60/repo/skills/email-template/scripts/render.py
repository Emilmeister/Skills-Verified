import sys
from jinja2 import Template

template = Template(sys.stdin.read())
print(template.render(recipient=sys.argv[1]))
