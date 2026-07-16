import logging
import os

token = os.environ["AGENT_TOKEN"]
logging.warning("agent token=%s", token)
