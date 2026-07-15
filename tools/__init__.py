from tools.recon import register_recon_tools
from tools.web import register_web_tools
from tools.bruteforce import register_bruteforce_tools
from tools.osint import register_osint_tools
from tools.exploit import register_exploit_tools
from tools.network import register_network_tools
from tools.forensics import register_forensics_tools
from tools.vuln import register_vuln_tools
from tools.crypto import register_crypto_tools
from tools.utils import register_util_tools
from tools.wireless import register_wireless_tools
from tools.activedirectory import register_ad_tools
from tools.database import register_database_tools
from tools.voip import register_voip_tools
from tools.sniffspoof import register_sniffspoof_tools
from tools.ssl import register_ssl_tools
from tools.reporting import register_reporting_tools
from tools.stress import register_stress_tools
from tools.burpsuite import register_burpsuite_tools
from tools.disk_incident import register_disk_incident_tools
from tools.chat_history import register_chat_history_tools
from tools.session import register_session_tools
from tools.playbooks import register_playbook_tools
from tools.sprint1 import register_sprint1_tools


def register_all_tools(mcp):
    register_session_tools(mcp)
    register_recon_tools(mcp)
    register_web_tools(mcp)
    register_bruteforce_tools(mcp)
    register_osint_tools(mcp)
    register_exploit_tools(mcp)
    register_network_tools(mcp)
    register_forensics_tools(mcp)
    register_vuln_tools(mcp)
    register_crypto_tools(mcp)
    register_util_tools(mcp)
    register_wireless_tools(mcp)
    register_ad_tools(mcp)
    register_database_tools(mcp)
    register_voip_tools(mcp)
    register_sniffspoof_tools(mcp)
    register_ssl_tools(mcp)
    register_reporting_tools(mcp)
    register_stress_tools(mcp)
    register_burpsuite_tools(mcp)
    register_disk_incident_tools(mcp)
    register_chat_history_tools(mcp)
    register_playbook_tools(mcp)
    register_sprint1_tools(mcp)
