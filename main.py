import subdomain_takeover
import multiprocessing
from itertools import repeat
import os
import json
import argparse



def main():

    # Get root domain from command line
    parser = argparse.ArgumentParser()  
    parser.add_argument('--root_domain', type=str)  
    parser.add_argument('--count_stats', type=bool, default=False)  
    args = parser.parse_args()
    root_domain = args.root_domain
    count_stats = args.count_stats

    if count_stats:
        subdomain_takeover.takeover_statistics(root_domain)
    
    else:
        # Generate subdomains
        subdomains = subdomain_takeover.generate_subdomains(root_domain)
        # subdomain_takeover.detect_risk(subdomains[0])

        with multiprocessing.Manager() as manager:
            subdomains_dict = manager.dict()
            with manager.Pool(8) as pool:
                pool.starmap(subdomain_takeover.detect_risk, zip(repeat(subdomains_dict,len(subdomains)), subdomains))
            
            dictionary = dict(subdomains_dict)

        
        # Save files
        dictionary_path = root_domain + ".json"

        with open(dictionary_path, "w") as f:
            json.dump(dictionary, f)



if __name__ == "__main__":
    main()