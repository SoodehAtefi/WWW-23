# The Benefits of Vulnerability Discovery and Bug Bounty Programs: Case Studies of Chromium and Firefox
This project contains the source code and dataset for the paper 'The Benefits of Vulnerability Discovery and Bug Bounty Programs: Case Studies of Chromium and Firefox' accepted in the WEB Conference (WWW 2023).
# Replication
To replicate the analysis performed in the paper run ./data_analysis/statistics_Chromium.py for Chromium and ./data_analysis/statistics_Firefox.py for Firefox.
## Structure
```
.
├── data_collection        # contains scripts for Firefox data collection, Chromium git sources, and Chromium weakness types
├── data_cleaning          # contains scripts for Firefox data cleaning, cleaning Chromium git sources, and cleaning Chromium weakness types
├── data_analyses          # contains scripts for all of the analysis performed in the paper
├── results folder         # contains results of the performed analysis
├── datasets folder        # contains cleaned data for performing analysis
├── data contains          # files created during data collection
├── Chromium_data_collection_and_cleaning          # contains scripts for Chromium data collection and cleaning
├── HEADER.py contains     # imported packages needed to run the scripts


