# bulk-mitigate

A script which performs bulk mitigation actions across Veracode applications, allowing you to update findings in batch.

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python bulk-mitigate.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python bulk-mitigate.py (arguments)

Arguments supported include:
* `--input_file`  Path to the Excel file containing findings to mitigate
* `--mitigation_proposal_comment` Mitigation proposal text to apply to each finding
* `--mitigation_approval_comment` Mitigation approval comment to apply to each finding
* `--mitigation_type` Type of mitigation to apply to each finding ("FP", "APPDESIGN", "OSENV", "NETENV", "LIBRARY", "ACCEPTRISK")