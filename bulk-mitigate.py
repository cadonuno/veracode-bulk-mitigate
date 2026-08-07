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
            try_propose_mitigation(application_guid, issue_list, mitigation_proposal, mitigation_type, attempt + 1)
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

def main():
    IS_DEBUG = False  # Set to True for debugging with hardcoded values
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

    for application_name, flaw_ids in app_name_to_itens_to_mitigate.items():
        print(f"Processing application: {application_name}")
        application_guid = try_get_application_guid(application_name)
        if application_guid:
            print(f"  Found application GUID: {application_guid}")
            if try_propose_mitigation(application_guid, flaw_ids, mitigation_proposal, mitigation_type):
                try_approve_mitigation(application_guid, flaw_ids, mitigation_approval_comment)

if __name__ == "__main__":
    main()
    