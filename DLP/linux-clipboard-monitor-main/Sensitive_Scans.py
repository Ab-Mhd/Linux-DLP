import re
import argparse
import logging

### Function Call Section ###

def handle_financial(file_Contents):
    logging.info("### Scanning for Financial Matches ###")
    found = []
    found.extend(find_Possible_Debit_Card_Numbers(file_Contents))
    found.extend(find_Possible_Credit_Card_Numbers(file_Contents))
    return found

def handle_personal(file_Contents):
    logging.info("### Scanning for Personal Matches ###")
    found = []
    found.extend(find_Possible_SIN_Numbers(file_Contents))
    found.extend(find_Possible_Passport_Numbers(file_Contents))
    return found
    
def handle_health(file_Contents):
    logging.info("### Scanning for Health Matches ###")
    return validate_health_card(file_Contents)
    
def handle_undetermined(file_Contents):
    logging.info("### Scanning for Undetermined Matches ###")
    return []

def handle_all(file_Contents):
    logging.info("### Scanning for All Matches ###")
    found = []
    found.extend(find_Possible_SIN_Numbers(file_Contents))
    found.extend(find_Possible_Debit_Card_Numbers(file_Contents))
    found.extend(find_Possible_Credit_Card_Numbers(file_Contents))
    found.extend(validate_health_card(file_Contents))
    found.extend(find_Possible_Passport_Numbers(file_Contents))	
    return found

### Function Section ###

## Luhn Algo ##

def filter_luhn_valid(numbers):
    def check_luhn(card_number):
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        card_number = re.sub(r'\D', '', card_number)
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        
        return checksum % 10 == 0

    return [number for number in numbers if check_luhn(number)]

## Financial Functions ##

# Debit Card #
def find_Possible_Debit_Card_Numbers(file_Contents):
    possible_Debit_Cards = re.findall(r'\d{4} \d{4} \d{4} \d{4}\b|\d{16}$', file_Contents)
    valid_Debit_Cards = filter_luhn_valid(possible_Debit_Cards)

    results = []
    for debit_Card_Number in valid_Debit_Cards:
        start_location = file_Contents.find(debit_Card_Number)
        length_of_match = len(debit_Card_Number)
        results.append(("Debit Card", start_location, length_of_match))
    
    return results

# Credit Card #
def find_Possible_Credit_Card_Numbers(file_Contents):
    possible_Credit_Cards = re.findall(r'\d{13,19}$|\b\d{4} \d{4} \d{4} \d{4}\b|\d{5}[-]?\d{4}[-]?\d{4}', file_Contents)
    iin_to_issuer = {
        '4': 'Visa',
        '51': 'MasterCard',
        '52': 'MasterCard',
        '53': 'MasterCard',
        '54': 'MasterCard',
        '55': 'MasterCard',
        '34': 'American Express',
        '37': 'American Express',
        '65': 'Discover',
        '6011': 'Discover',
        '644': 'Discover',
        '645': 'Discover',
        '646': 'Discover',
        '647': 'Discover',
        '648': 'Discover',
        '649': 'Discover',
        '35': 'JCB',
        '2131': 'JCB',
        '1800': 'JCB',
        '36': 'Diners Club',
        '38': 'Diners Club'
    }
    def get_issuer(number):
        for iin in sorted(iin_to_issuer.keys(), key=len, reverse=True):
            if number.startswith(iin):
                return iin_to_issuer[iin], iin
        return "Unknown", "N/A"
        
    valid_Credit_Cards = filter_luhn_valid(possible_Credit_Cards)
    
    results = []
    for credit_Card_Number in valid_Credit_Cards:
        start_location = file_Contents.find(credit_Card_Number)
        length_of_match = len(credit_Card_Number)
        results.append(("Credit Card", start_location, length_of_match))
    
    return results

## Personal Functions ##

# Passport #
def find_Possible_Passport_Numbers(file_Contents):
    possible_Passport_Numbers = re.findall(r'[A-Za-z]{2}\d{6}|[A-Za-z]{1}\d{6}[A-Za-z]{2}', file_Contents)

    results = []
    for passport_number in possible_Passport_Numbers:
        start_location = file_Contents.find(passport_number)
        length_of_match = len(passport_number)
        results.append(("Passport", start_location, length_of_match))
    
    return results

# SIN Number #
def find_Possible_SIN_Numbers(file_Contents):
    possible_sins = re.findall(r'\d{9}', file_Contents)
    valid_sins = filter_luhn_valid(possible_sins)

    results = []
    for sin in valid_sins: 
        start_location = file_Contents.find(sin)
        length_of_match = len(sin)
        results.append(("SIN", start_location, length_of_match))
    
    return results

## Health Functions ##

# Health Card #
def validate_health_card(file_Contents):
    patterns_for_health_cards = [
        (r'\d{4}[- ]?\d{3}[- ]?\d{3}', 'Ontario'),
        (r'[A-Z]{4}\d{8}', 'Quebec'),
        (r'\d{10}', 'British Columbia'),
        (r'\d{9}', 'Alberta')
    ]

    possible_Health_Cards = []

    for pattern, province in patterns_for_health_cards:
        matches = re.findall(pattern, file_Contents)
        possible_Health_Cards.extend([(match, province) for match in matches])

    valid_Health_Cards = filter_luhn_valid([hc[0] for hc in possible_Health_Cards])

    results = []
    for health_Card_Number in valid_Health_Cards:
        start_location = file_Contents.find(health_Card_Number)
        length_of_match = len(health_Card_Number)
        results.append(("Health Card", start_location, length_of_match))
    
    return results

## Main Section ###

# File Read 
def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        print(f"The file at {file_path} was not found.")
        content = ""
    except IOError:
        print(f"An error occurred while trying to read the file at {file_path}.")
        content = ""

    return content

# Function to tag categories
def tags(file_Contents):
    categories = {
        "Financial": handle_financial,
        "Personal": handle_personal,
        "Health": handle_health,
        "Undetermined": handle_undetermined
    }
    
    found_tags = []
    for category, handler in categories.items():
        found_tags.extend(handler(file_Contents))
    
    logging.info(f"Tags Found: {found_tags}")
    return found_tags

# Main function to handle command line arguments
def main():
    parser = argparse.ArgumentParser(description="Scan a file for different types of sensitive information.")
    parser.add_argument("file_path", help="The path to the file to scan")
    parser.add_argument("category", choices=["Financial", "Personal", "Health", "Undetermined", "All", "Tags"], 
                        help="The category of information to scan for")
    parser.add_argument("output_file", help="The path to the output file")

    args = parser.parse_args()

    logging.basicConfig(filename=args.output_file, level=logging.INFO, format='%(message)s')

    file_Contents = read_file(args.file_path)

    if not file_Contents:
        print("No content to scan.")
        return

    categories = {
        "Financial": handle_financial,
        "Personal": handle_personal,
        "Health": handle_health,
        "Undetermined": handle_undetermined,
        "All": handle_all,
        "Tags": tags
    }
    
    results = categories[args.category](file_Contents)

    if args.category == "Tags":
        print(results)
    else:
        with open(args.output_file, 'a') as output_file:
            for category, location, length in results:
                found_item = file_Contents[location:location+length]
                output_line = f"Possible {category}: {found_item}, Location in File: {location}"
                print(output_line)
                output_file.write(output_line + "\n")

if __name__ == "__main__":
    main()
