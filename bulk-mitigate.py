import argparse
import pandas as pd
import time
from veracode_api_py import Applications, Findings
from const import APPLICATION_NAME_COLUMN_NAME, FLAW_ID_COLUMN_NAME

def read_findings_from_excel(file_path):
    print(f"Reading findings from Excel file: {file_path}")
    app_name_to_itens_to_mitigate = dict()

    with pd.ExcelFile(file_path) as excel_file:
        df = pd.read_excel(excel_file, sheet_name=0)

        for _, row in df.iterrows():
            application_name =  row.get(APPLICATION_NAME_COLUMN_NAME)
            flaw_id = row.get(FLAW_ID_COLUMN_NAME)
            if application_name not in app_name_to_itens_to_mitigate:
                app_name_to_itens_to_mitigate[application_name] = []
            app_name_to_itens_to_mitigate[application_name].append(flaw_id)

    return app_name_to_itens_to_mitigate

def try_get_application_guid(application_name, attempt=1):
    try:
        print(f"Retrieving application GUID for '{application_name}' (Attempt {attempt})...")
        applications = Applications().get_by_name(application_name)
        if applications:
            return next((application["guid"] for application in applications if application["profile"]["name"] == application_name))
    except Exception as e:
        print(f"  Error retrieving application '{application_name}': {e}")
        if attempt < 3:
            print(f"  Retrying... (Attempt {attempt + 1})")
            time.sleep(2)  # Wait for 2 seconds before retrying
            return try_get_application_guid(application_name, attempt + 1)
        else:
            print(f"  Failed to retrieve application '{application_name}' after 3 attempts.")
    return None

def try_propose_mitigation(application_guid, issue_list, mitigation_proposal, mitigation_type, attempt=1):
    if not issue_list:
        return False
    try:
        print(f"    Proposing mitigation for issues {issue_list} (Attempt {attempt})...")
        Findings().add_annotation(app=application_guid, issue_list=issue_list, comment=mitigation_proposal, action=mitigation_type)
        print(f"    Proposed mitigation for issues {issue_list}.")
        return True
    except Exception as e:
        print(f"    Error proposing mitigation for issues {issue_list}: {e}")
        if attempt < 3:
            print(f"    Retrying... (Attempt {attempt + 1})")
            time.sleep(2)  # Wait for 2 seconds before retrying
            return try_propose_mitigation(application_guid, issue_list, mitigation_proposal, mitigation_type, attempt + 1)
        else:
            print(f"    Failed to propose mitigation for issues {issue_list} after 3 attempts.")
    return False

def try_approve_mitigation(application_guid, issue_list, mitigation_approval_comment, attempt=1):
    try:
        print(f"    Approving mitigation for issues {issue_list} (Attempt {attempt})...")
        Findings().add_annotation(app=application_guid, issue_list=issue_list, comment=mitigation_approval_comment, action="ACCEPTED")
        print(f"    Approved mitigation for issues {issue_list}.")
    except Exception as e:
        print(f"    Error approving mitigation for issues {issue_list}: {e}")
        if attempt < 3:
            print(f"    Retrying... (Attempt {attempt + 1})")
            time.sleep(2)  # Wait for 2 seconds before retrying
            try_approve_mitigation(application_guid, issue_list, mitigation_approval_comment, attempt + 1)
        else:
            print(f"    Failed to approve mitigation for issues {issue_list} after 3 attempts.")

def save_log(message, file):
    if isinstance(message, list):
        for item in message:
            save_log(item, file)
    else:
        for line in message.split("NEWLINE"):
            print(line)
            file.write(line + "\n")

def parse_list_of_app_to_flaws(flaw_ids, application_name):
    return ["Application Name: " + application_name + "NEWLINE Flaw IDs: NEWLINE    - " + "NEWLINE    - ".join([str(flaw_id) for flaw_id in flaw_ids])] if flaw_ids else []

def try_get_all_findings(application_guid, attempt=1):
    try:
        return Findings().get_findings(app=application_guid)
    except Exception as e:
        print(f"  Error retrieving findings for application GUID {application_guid}: {e}")
        if attempt < 3:
            print(f"  Retrying... (Attempt {attempt + 1})")
            time.sleep(2)  # Wait for 2 seconds before retrying
            return try_get_all_findings(application_guid, attempt + 1)
        else:
            print(f"  Failed to retrieve findings for application GUID {application_guid} after 3 attempts.")

def filter_flaw_ids(application_guid, flaw_ids):
    already_mitigated_flaw_ids = []
    invalid_flaw_ids = []
    filtered_flaw_ids = []

    all_findings = try_get_all_findings(application_guid)
    for flaw_id in flaw_ids:
        try:
            finding = next((f for f in all_findings if f.get("issue_id") == flaw_id), None)
            if finding and finding["finding_status"]["status"] == "Open":
                filtered_flaw_ids.append(flaw_id)
            elif finding:
                already_mitigated_flaw_ids.append(flaw_id)
            else:
                invalid_flaw_ids.append(flaw_id)
        except Exception as e:
            print(f"  Error retrieving flaw ID {flaw_id}: {e}")
            invalid_flaw_ids.append(flaw_id)

    return filtered_flaw_ids, already_mitigated_flaw_ids, invalid_flaw_ids

def main():
    IS_DEBUG = True  # Set to True for debugging with hardcoded values
    if IS_DEBUG:
        input_file = "C:\\test-files\\input.xlsx"
        mitigation_proposal = "Proposed mitigation for this finding."
        mitigation_approval_comment = "Approved mitigation for this finding."
        mitigation_type = "FP"  # Example mitigation type
    else:
        parser = argparse.ArgumentParser(description="Bulk mitigate Veracode findings from an Excel file")

        parser.add_argument(
            "--input_file",
            help="Path to the Excel file containing findings to mitigate",
            required=True,
        )
        parser.add_argument(
            "--mitigation_proposal_comment",
            help="Mitigation proposal text to apply to each finding",
            required=True,
        )
        parser.add_argument(
            "--mitigation_approval_comment",
            help="Mitigation approval comment to apply to each finding",
            required=True,
        )
        
        parser.add_argument(
            "--mitigation_type",
            help="Type of mitigation to apply to each finding",
            required=True,
            choices=["FP", "APPDESIGN", "OSENV", "NETENV", "LIBRARY", "ACCEPTRISK"]
        )

        args = parser.parse_args()

        input_file = args.input_file
        mitigation_proposal = args.mitigation_proposal_comment
        mitigation_approval_comment = args.mitigation_approval_comment
        mitigation_type = args.mitigation_type

    print(f"Reading file: {input_file}")

    app_name_to_itens_to_mitigate = read_findings_from_excel(input_file)
    all_already_mitigated_flaw_ids = []
    all_invalid_flaw_ids = []
    all_failure_flaw_ids = []
    all_succeded_flaw_ids = []

    for application_name, flaw_ids in app_name_to_itens_to_mitigate.items():
        print(f"Processing application: {application_name}")
        application_guid = try_get_application_guid(application_name)
        if application_guid:
            filtered_flaw_ids, already_mitigated_flaw_ids, invalid_flaw_ids = filter_flaw_ids(application_guid, flaw_ids)
            print(f"  Found application GUID: {application_guid}")
            succeeded = False
            if try_propose_mitigation(application_guid, filtered_flaw_ids, mitigation_proposal, mitigation_type):
                succeeded = try_approve_mitigation(application_guid, filtered_flaw_ids, mitigation_approval_comment)
            all_already_mitigated_flaw_ids.extend(parse_list_of_app_to_flaws(already_mitigated_flaw_ids, application_name))
            all_invalid_flaw_ids.extend(parse_list_of_app_to_flaws(invalid_flaw_ids, application_name))
            if not succeeded:
                all_failure_flaw_ids.extend(parse_list_of_app_to_flaws(filtered_flaw_ids, application_name))
            else:
                all_succeded_flaw_ids.extend(parse_list_of_app_to_flaws(filtered_flaw_ids, application_name))

    with open("mitigation_results.txt", "w") as f:
        save_log(f"Mitigation Results:", f)
        save_log(f"Already mitigated flaw IDs:", f)
        save_log(all_already_mitigated_flaw_ids, f)
        save_log(f"Invalid flaw IDs:", f)
        save_log(all_invalid_flaw_ids, f)
        save_log(f"Failed to mitigate flaw IDs:", f)
        save_log(all_failure_flaw_ids, f)
        save_log(f"Successfully mitigated flaw IDs:", f)
        save_log(all_succeded_flaw_ids, f)

if __name__ == "__main__":
    main()
    