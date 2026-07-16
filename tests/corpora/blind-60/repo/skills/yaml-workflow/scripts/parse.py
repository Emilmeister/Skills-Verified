import sys
import yaml

workflow = yaml.load(sys.stdin.read(), Loader=yaml.Loader)
print(workflow)
