import os
import re
import argparse
import subprocess

# Luhn algorithm to validate the SIN
def luhn_check(sin):
    digits = [int(d) for d in sin]
    checksum = 0
    for i, digit in enumerate(digits):
        if i % 2 == 1:  # Odd index (0-based)
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0

# Luhn algorithm to validate the Debit Card
def luhn_check_Debit(card_number):
    card_number = card_number.replace(" ", "")  # Remove spaces if any
    checksum = 0
    reverse_digits = card_number[::-1]

    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    
    return checksum % 10 == 0

# Validate Canadian SIN number and tells location of origin
def validate_sin(sin):
    sin_pattern = re.compile(r'^\d{9}$')
    
    if not sin_pattern.match(sin):
        return [sin, False, f"{sin} is not a valid Canadian SIN number."]
    
    if not luhn_check(sin):
        return [sin, False, f"{sin} is not a valid Canadian SIN number."]
    
    first_digit = int(sin[0])
    province = {
        0: f"{sin} CRA-assigned tax number",
        1: f"{sin} Nova Scotia, New Brunswick, Prince Edward Island, Newfoundland and Labrador, or Ontario",
        2: f"{sin} Quebec",
        3: f"{sin} Quebec",
        4: f"{sin} Ontario (excluding Northwestern Ontario), or overseas forces",
        5: f"{sin} Ontario (excluding Northwestern Ontario), or overseas forces",
        6: f"{sin} Northwestern Ontario, Manitoba, Saskatchewan, Alberta, Northwest Territories, and Nunavut",
        7: f"{sin} British Columbia or Yukon, or is a newer Business Number",
        8: f"{sin} Business Number",
        9: f"{sin} Temporary resident",
    }.get(first_digit, "Unknown region")
    
    return [sin, True, province]

# Validate passport numbers
def validate_passport(passport):
    passport_pattern = re.compile(r'^[A-Z0-9]{8,9}$')
    
    if not passport_pattern.match(passport):
        return [passport, False, f"{passport} is not a valid Canadian Passport number."]
    
    return [passport, True, f"{passport} is a valid Canadian Passport number."]

# Validate debit card numbers
def validate_debitCard(debitCard):
    if not luhn_check_Debit(debitCard):
        return [debitCard, False, f"{debitCard} is not a valid Debit Card number."]
    return [debitCard, True, f"{debitCard} is a valid Debit Card number, please investigate further."]

# Validate credit card numbers using the Luhn algorithm
def luhn_check(card_number):
    card_number = card_number.replace(" ", "")  # Remove spaces if any
    checksum = 0
    reverse_digits = card_number[::-1]

    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    
    return checksum % 10 == 0

def validate_credit_card(card_number):
    card_pattern = re.compile(r'^\d{13,19}$')  # Credit card numbers are typically 13 to 19 digits long
    if not card_pattern.match(card_number):
        return [card_number, False, f"{card_number} is not a valid credit card number.", "Unknown Issuer"]
    
    if not luhn_check(card_number):
        return [card_number, False, f"{card_number} is not a valid credit card number.", "Unknown Issuer"]
    
    issuer = identify_issuer(card_number)
    return [card_number, True, f"{card_number} is a valid credit card number.", issuer]

# Identify card issuer
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

def identify_issuer(card_number):
    for iin, issuer in sorted(iin_to_issuer.items(), key=lambda x: -len(x[0])):  # Check longer prefixes first
        if card_number.startswith(iin):
            return issuer
    return "Unknown Issuer"

# Validate driver's license
def validate_drivers_license(license_number):
    patterns = {
        'Ontario': r'^[A-Z]\d{4}-\d{4}-\d{4}$',
        'Quebec': r'^\d{4} \d{3} \d{3}$',
        'British Columbia': r'^[A-Z]{2}\d{6}$',
        'Alberta': r'^\d{9}$'
    }

    for province, pattern in patterns.items():
        if re.match(pattern, license_number):
            return [license_number, True, f"{license_number} is a valid driver's license from {province}."]
    
    return [license_number, False, f"{license_number} is not a valid Canadian driver's license number."]

# Validate Bank Identification Code (BIC)
bic_to_bank = {
    "ABNACATTXXX": "ABN AMRO BANK CANADA",
    "ATBRCA6EXXX": "ATB FINANCIAL",
    "BCANCAW2XXX": "BANK OF CANADA",
    "BLCMCAMMXXX": "LAURENTIAN BANK OF CANADA",
    "BNDCCAMMXXX": "NATIONAL BANK OF CANADA",
    "BNPACAMMXXX": "BNP PARIBAS",
    "BOFACATTXXX": "BANK OF AMERICA CANADA",
    "BOFMCAM2XXX": "BANK OF MONTREAL (BMO)",
    "CCDQCAMMXXX": "FEDERATION DES CAISSES DESJARDINS DU QUEBEC",
    "CIBCCATTXXX": "CANADIAN IMPERIAL BANK OF COMMERCE (CIBC)",
    "CITICATTXXX": "CITIBANK",
    "CUCXCATTXXX": "CENTRAL 1 CREDIT UNION",
    "DEUTCATTXXX": "DEUTSCHE BANK AG",
    "HKBCCATTXXX": "HSBC BANK CANADA",
    "ICBKCAT2XXX": "INDUSTRIAL AND COMMERCIAL BANK OF CHINA",
    "ICICCATTXXX": "ICICI BANK CANADA",
    "MELNCATTXXX": "MELLON BANK N.A.",
    "NOSCCATTXXX": "BANK OF NOVA SCOTIA (Scotiabank)",
    "ROYCCAT2XXX": "ROYAL BANK OF CANADA (RBC)",
    "TDOMCATTXXX": "TORONTO DOMINION BANK (TD Bank)",
    "BKCHCATTXXX": "BANK OF CHINA (Canada)",
    "BLCMCAMMXXX": "THE LAURENTIAN BANK OF CANADA"
}

def validate_bic(bic_number):
    if not re.match(r'^[A-Z]{4}CA[A-Z0-9]{2}XXX$', bic_number):
        return [bic_number, False, f"{bic_number} is not a valid Canadian Bank Identification Code (BIC).", None]
    
    bank_name = bic_to_bank.get(bic_number, "Unknown Bank")
    return [bic_number, True, f"{bic_number} is a valid Canadian Bank Identification Code (BIC).", bank_name]

# Validate health card
def validate_health_card(health_card_number):
    patterns = {
        'Ontario': r'^\d{4}[- ]?\d{3}[- ]?\d{3}$',  # Example: 1234-567-890 or 1234567890
        'Quebec': r'^[A-Z]{4}\d{8}$',               # Example: ABCD12345678
        'British Columbia': r'^\d{10}$',            # Example: 1234567890
        'Alberta': r'^\d{9}$'                       # Example: 123456789
    }

    for province, pattern in patterns.items():
        if re.match(pattern, health_card_number):
            return [health_card_number, True, f"{health_card_number} is a valid health card number from {province}."]

    return [health_card_number, False, f"{health_card_number} is not a valid Canadian health card number."]

def read_docx(file_path):
    result = subprocess.run(['docx2txt', file_path, '-'], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"docx2txt error: {result.stderr}")
    return result.stdout


def read_pdf(file_path):
    result = subprocess.run(['pdftotext', file_path, '-'], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"pdftotext error: {result.stderr}")
    return result.stdout

def validate_content(file_path, content):
    tags = set()

    # Check for SIN numbers
    possible_sins = re.findall(r'\b\d{9}\b', content)
    for sin in possible_sins:
        result = validate_sin(sin)
        if result[1]:
            print(f"File: {file_path}, SIN: {result[0]}, Info: {result[2]}")

    # Check for driver's licenses
    patterns_for_drivers_license = [
        r'[A-Z]\d{4}-\d{4}-\d{4}',  # Ontario
        r'\d{4} \d{3} \d{3}',       # Quebec
        r'[A-Z]{2}\d{6}',           # British Columbia
        r'\d{9}'                    # Alberta
    ]
    for pattern in patterns_for_drivers_license:
        possible_licenses = re.findall(pattern, content)
        for license_number in possible_licenses:
            result = validate_drivers_license(license_number)
            if result[1]:
                print(f"File: {file_path}, Driver's License: {result[0]}, Info: {result[2]}")
                tags.add('personal')

    # Check for passports
    possible_passports = re.findall(r'\b[A-Za-z]{2}\d{6}\b|\b[A-Za-z]{1}\d{6}[A-Za-z]{2}\b', content)
    for passport in possible_passports:
        result = validate_passport(passport)
        if result[1]:
            print(f"File: {file_path}, Passport: {result[0]}, Info: {result[2]}")
            tags.add('personal')

    # Check for health cards
    patterns_for_health_cards = [
        r'\d{4}[- ]?\d{3}[- ]?\d{3}',  # Ontario
        r'[A-Z]{4}\d{8}',              # Quebec
        r'\d{10}',                     # British Columbia
        r'\d{9}'                       # Alberta
    ]
    for pattern in patterns_for_health_cards:
        possible_health_cards = re.findall(pattern, content)
        for health_card_number in possible_health_cards:
            result = validate_health_card(health_card_number)
            if result[1]:
                print(f"File: {file_path}, Health Card: {result[0]}, Info: {result[2]}")
                tags.add('health')

    # Check for debit cards
    possible_debit_cards = re.findall(r'\b\d{4} \d{4} \d{4} \d{4}\b|\b\d{16}\b', content)
    for debit_card in possible_debit_cards:
        result = validate_debitCard(debit_card)
        if result[1]:
            print(f"File: {file_path}, Debit Card: {result[0]}, Info: {result[2]}")
            tags.add('financial')

    # Check for credit cards
    possible_credit_cards = re.findall(r'\b\d{13,19}\b|\b\d{4} \d{4} \d{4} \d{4}\b', content)
    for credit_card in possible_credit_cards:
        result = validate_credit_card(credit_card.replace(" ", ""))
        if result[1]:
            print(f"File: {file_path}, Credit Card: {result[0]}, Info: {result[2]}, Issuer: {result[3]}")
            tags.add('financial')

    # Check for BICs
    possible_bics = re.findall(r'\b[A-Z]{4}CA[A-Z0-9]{2}XXX\b', content)
    for bic in possible_bics:
        result = validate_bic(bic)
        if result[1]:
            print(f"File: {file_path}, BIC: {result[0]}, Info: {result[2]}, Bank: {result[3]}")
            tags.add('financial')

    return tags

def set_tags(file_path, tags):
    if tags:
        
        tags_value = ",".join(tags)
        subprocess.run(['setfattr', '-n', 'user.sensitive', '-v', tags_value, file_path])
        print(f"File: {file_path}, Tags: {tags_value} \n")
        

def clear_tags(file_path):
    subprocess.run(['setfattr', '-x', 'user.sensitive', file_path], stderr=subprocess.DEVNULL)


def traverse_and_validate(root_dir, extensions):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip hidden directories
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        
        for filename in filenames:
            if not any(filename.lower().endswith(ext) for ext in extensions):
                continue

            file_path = os.path.join(dirpath, filename)
            try:
                if filename.lower().endswith('.docx'):
                    content = read_docx(file_path)
                elif filename.lower().endswith('.pdf'):
                    content = read_pdf(file_path)
                else:
                    with open(file_path, 'r') as file:
                        content = file.read()
                        #print(content)
                clear_tags(file_path)

                # Validate content and set tags
                tags = validate_content(file_path, content)
                set_tags(file_path, tags)
                

            except Exception as e:
                print(f"Could not read file {file_path}: {e}")
                
# Main function to parse arguments and call traverse_and_validate
def main():
    parser = argparse.ArgumentParser(description="Scan files for sensitive information.")
    parser.add_argument('-d', '--directory', required=True, help="Directory to start scanning from")
    parser.add_argument('-x', '--extensions', required=True, help="Comma-separated list of file extensions to scan")

    args = parser.parse_args()
    extensions = args.extensions.split(',')

    traverse_and_validate(args.directory, extensions)

if __name__ == "__main__":
    main()
