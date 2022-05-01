"""
Utilizing amass to generate subdomains of a root domain website, and detect if there is a pontential threat.
"""

from logging import root
import os
import requests
import json

#errorTexts referred from public github repo
vuln_sentences = [
    "The specified bucket does not exit ",
       "Repository not found ",
       "ERROR\: The request could not be satisfied ",
       "There isn't a GitHub Pages site here.",
       "Sorry\, this shop is currently unavailable\. ",
       "Sorry\, We Couldn't Find That Page ",
       "Fastly error\: unknown domain\: ",

       "The feed has not been found\. ",
       "The thing you were looking for is no longer here\, or never was ",
       "no-such-app.html|<title>no such app</title>|herokucdn.com/error-pages/no-such-app.html ",
       "The gods are wise, but do not know of the site which you seek. ",
       "Whatever you were looking for doesn't currently exist at this address. ",
       "Do you want to register ",
       "Help Center Closed ",

       "Oops - We didn't find your site. ",
       "We could not find what you're looking for. ",
       "No settings were found for this company: ",
       "The specified bucket does not exist ",
       "<title>404 &mdash; File not found</title> ",
       "You are being <a href=\"https://www.statuspage.io\">redirected ",
       "This UserVoice subdomain is currently available! ",
       "project not found ",
       "This page is reserved for artistic dogs\.|Uh oh\. That page doesn't exist</h1> ",

       "<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p> ",
       "<h1>The page you were looking for doesn't exist.</h1> ",
       "You may have mistyped the address or the page may have moved. ",
       "<h1>Error 404: Page Not Found</h1> ",

       "<h1>https://www.wishpond.com/404?campaign=true ",
       "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist. ",
       "There is no portal here \.\.\. sending you back to Aha! ",
       "to target URL: <a href=\"https://tictail.com|Start selling on Tictail. ",
       "<p class=\"bc-gallery-error-code\">Error Code: 404</p> ",
       "<h1>Oops! We couldn&#8217;t find that page.</h1> ",
       "alt=\"LIGHTTPD - fly light.\" ",

       "Double check the URL or <a href=\"mailto:help@createsend.com ",
       "The site you are looking for could not be found.|If you are an Acquia Cloud customer and expect to see your site at this address ",
       "If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz ",
       "We can't find this <a href=\"https://simplebooklet.com ",
       "With GetResponse Landing Pages, lead generation has never been easier ",
       "Looks like you've traveled too far into cyberspace. ",
       "is not a registered InCloud YouTrack. ",

       "The requested URL / was not found on this server|The requested URL was not found on this server ",
       "Domain is not configured ",
       "pingdom ",
       "Domain has been assigned ",
       "data-html-name ",
       "Unrecognized domain <strong> ",
]


def generate_subdomains(root_domain):
    
    """
    Generate subdomains using amass.

    root_domain: domain that is used for find all subdomains.

    return a list of all subdomains
    """

    # Check if subdomain is generated
    subdomain_path = root_domain.split(".")[0] + ".txt"
    
    if os.path.exists(subdomain_path):

        print("Subdomains of %s have been generated, now loading!" %(root_domain))
        with open(subdomain_path, "r") as f:
            generate_subdomains = [line.rstrip() for line in f]
        
    else:

        # Run amass to generate subdomains
        generate_subdomains_cmd = "amass enum -passive -d " + root_domain + " > " + subdomain_path
        print("Start generaing subdomains of %s" %(root_domain))
        generate_subdomains = os.system(generate_subdomains_cmd)

        # 
        with open(subdomain_path, "r") as f:
            generate_subdomains = f.readlines()

    return generate_subdomains



def detect_risk(subdomain_dict, subdomain):
    
    """
    Check potential vulnerabilities by checking the signatures of subdomain.
    """

    # Initilizaton
    status = ""
    subdomain = subdomain.replace("\n","")

    try:
        # Send http requests
        response = requests.get("http://"+subdomain, timeout=20).text
        status = "successful connection"
        print("Successful connection: " + subdomain)
        
        # Check if there is error message in the response text
        for err in vuln_sentences:

            # If error message detected
            if err in response:
                print("Potential Vulnerbility Detected:" + subdomain)
                status = "detected vulnerability "
                break

    # HTTP request connection error
    except requests.exceptions.ConnectionError:
        status = "failed connection "
        print("Not Found: " + subdomain)
    
    # HTTP timeout error
    except requests.exceptions.Timeout:
        status = "real timeout"
        print("Real Timeout: " + subdomain)
    
    except requests.exceptions.TooManyRedirects:
        status = "too many redirects"
        

    
    subdomain_dict[subdomain] = status 
    
    

def takeover_statistics(root_domain):

    """
    Count the basic statistics of subdomains
    """

    # All subdomains
    subdomains_takeover_path = root_domain + ".json"

    if not os.path.exists(subdomains_takeover_path):
        print("%s.json file does not exist, run with out --count_stats first!" %(root_domain))
        os._exit(0)

    with open(subdomains_takeover_path, "r") as f:
        subdomains_takeover = json.load(f)
    
    # Basic statistics of subdomains
    num_subdomains = len(subdomains_takeover.keys())
    subdomains_takeover_values = list(subdomains_takeover.values())
    num_failed_connection = subdomains_takeover_values.count("failed connection ")
    num_successful_connection = subdomains_takeover_values.count("successful connection")
    num_detected_vuln = subdomains_takeover_values.count("detected vulnerability ")
    num_real_timeout = subdomains_takeover_values.count("real timeout")
    num_many_redirects = subdomains_takeover_values.count("too many redirects")

    print("Root domain: %s" %(root_domain))
    print("Number of subdomains: %d" %(num_subdomains))
    print("Number of failed connection: %d" %(num_failed_connection))
    print("Number of successful connection: %d" %(num_successful_connection))
    print("Number of detected vulnerability: %d" %(num_detected_vuln))
    print("Number of real timeout: %d" %(num_real_timeout))
    print("Number of too many redirects: %d" %(num_many_redirects))



