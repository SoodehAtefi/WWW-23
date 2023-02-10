from HEADER import *


#extract information in fields of a vulnerability information page in Bugzilla
def extracter(urls_ids):
    issue_summary = []
    status_now = []
    bug_id = []
    cve = []
    product = []
    component = []
    version = []
    platform = []
    platform2 = []
    type_issue = []
    priority = []
    severity = []
    status = []
    milestone = []
    assigne = []
    reporter = []
    triage_owner = []
    keywords = []
    whiteboard = []
    list_of_duplicates = []
    links_org = []
    opened_timestamp = []
    closed_timestamp = []
    opened_date = []
    closed_date = []
    not_valid_ids = []
    bounty = []
    flag_value = []
    t_nl_open = []
    t_nl_close = []
    whiteboard_details = []
#    tracking_flags = []
    tracking_flag_name_all=[]
    tracking_flag_tracking_all=[]
    tracking_flag_status_all=[]
    for url in tqdm.tqdm(urls_ids):
#        print(url)
        #to prevent timeouts
#        time.sleep(1.0+ np.random.uniform(0, 1))
        r = requests.get(url)
        data = r.text
        soup = BeautifulSoup(data,'lxml')
        if soup.find('td', class_='throw_error'):
            print("url is not available", url)
            not_valid_ids.append(url)
            continue
        else:
            d_time = soup.findAll('span', class_='bug-time-label')
            t_date = []
            t_timestamp = []
            t_nl_open.append(d_time[0].text)
            
            
            for x in d_time:
                t_info = x.find('span', class_='rel-time')
                t_date.append(t_info['title'])
                t_timestamp.append(t_info['data-time'])

            opened_timestamp.append(t_timestamp[0])
            opened_date.append(t_date[0])
            if len(d_time)>1:
                t_nl_close.append(d_time[1].text)
                closed_timestamp.append(t_timestamp[1])
                closed_date.append(t_date[1])
            else:
                t_nl_close.append('NA')
                closed_timestamp.append('NA')
                closed_date.append('NA')
            issue_summary.append(soup.find('span', id='field-value-short_desc').text)
            status_now.append(soup.find('span', class_='bug-status-label text').text)
            status_soup = soup.find('span', id='field-value-status-view')
            d_status = status_soup.findAll('a', attrs={"class": "bz_bug_link"})
            links_originals = []
            if status_soup.find('a', class_='bz_bug_link'):
                for x in d_status:
                    full_address = 'https://bugzilla.mozilla.org' + x['href']
                    links_originals.append(full_address)
                links_org.append(links_originals)
            else:
                links_org.append('NA')
            bug_id.append(soup.find('span', id='field-value-bug_id').text)
            d_cve = soup.find('span', class_='edit-hide')
            if d_cve != None:
                cve.append(soup.find('span', class_='edit-hide').text)
            else:
                cve.append('NA')

            product.append(soup.find("span", id="product-name").text)
            component.append(soup.find("span", id="component-name").text)
            version.append(soup.find("span", id="field-value-version").text)
            platform.append(soup.find("span", id="field-value-rep_platform").text)
            d_platform = soup.find("span", id="field-value-op_sys")
            if d_platform != None:
                platform2.append(soup.find("span", id="field-value-op_sys").text)
            else:
                platform2.append('NA')
            type_issue.append(soup.find("span", class_="bug-type-label iconic-text").text)
            priority.append(soup.find("span", id="field-value-priority").text)
            severity.append(soup.find("span", id="field-value-bug_severity").text)
            status.append(soup.find('span', id='field-value-status-view').text)
            milestone.append(soup.find('span', id='field-value-target_milestone').text)
            assigne.append(soup.find('span', id='field-value-assigned_to').text)
            reporter.append(soup.find('span', id='field-value-reporter').text)
            triage_owner.append(soup.find('span', id='field-value-triage_owner').text)
            details = soup.find('section', class_='module', id="module-details")
            if details != None:
                whiteboard_details.append(soup.find('span', id='field-value-status_whiteboard').text)
            else:
                whiteboard_details.append('NA')
            d_bug_flags = details.find(class_='field', id='field-bug_flags')
            if (details != None) and (d_bug_flags != None) and (details.find(class_='flag-name')):
                bounty.append(details.find(class_='flag-name').text)
                flag_value.append(details.find(class_='flag-value').text)
            else:
                bounty.append('NA')
                flag_value.append('NA')
            d_links_dups = soup.findAll('div', class_="field bug-list", id=None)
            if d_links_dups != None and soup.find('div', class_="field bug-list", id=None):
                li_dups = []
                for x in d_links_dups:
                    links_dups = x.findAll('a', attrs={"class": "bz_bug_link"})
                    for d in links_dups:
                        d_title = d['title']
                        if 'DUPLICATE' in d_title:
                            full_link = 'https://bugzilla.mozilla.org' + d['href']
                            li_dups.append(full_link)

                list_of_duplicates.append(li_dups)
            else:
                list_of_duplicates.append('NA')

            keywords.append(soup.find('span', id='field-value-keywords').text)
            whiteboard.append(soup.find('span', id='field-value-status_whiteboard').text)
            
 
            tracking_field=soup.find('div',{"id": "module-tracking-content"}).findAll('div',class_='fields-rhs')
            if tracking_field[0].find('div', class_='flags edit-hide'):
                table_tracking = tracking_field[0].find('div', class_='flags edit-hide')

                tracking_flag_name=table_tracking.findAll('td', class_='tracking-flag-name')
                tracking_flag_name=[td.text.strip() for td in tracking_flag_name if td.text.strip()]
                tracking_flag_tracking=table_tracking.findAll('td', class_='tracking-flag-tracking')
                tracking_flag_tracking=[td.text.strip() for td in tracking_flag_tracking if td.text.strip()]
                tracking_flag_status=table_tracking.findAll('td', class_='tracking-flag-status')
                tracking_flag_status=[td.text.strip() for td in tracking_flag_status if td.text.strip()]
                tracking_flag_name_all.append(','.join(tracking_flag_name))
                tracking_flag_tracking_all.append(','.join(tracking_flag_tracking))
                tracking_flag_status_all.append(','.join(tracking_flag_status))
            else:
                tracking_flag_name_all.append('NA')
                tracking_flag_tracking_all.append('NA')
                tracking_flag_status_all.append('NA')


    issue_info = pd.DataFrame()
    issue_info['Summary'] = issue_summary
    issue_info['StatusNow'] = status_now
    issue_info['BugID'] = bug_id
    issue_info['CVE'] = cve
    issue_info['Opened'] = opened_timestamp
    issue_info['Closed'] = closed_timestamp
    issue_info['TimeOpenend'] = opened_date
    issue_info['TimeClosed'] = closed_date
    issue_info['Product'] = product
    issue_info['Component'] = component
    issue_info['Version'] = version
    issue_info['Platform'] = platform
    issue_info['Platform2'] = platform2
    issue_info['Type'] = type_issue
    issue_info['Priority'] = priority
    issue_info['Severity'] = severity
    issue_info['Milestone'] = milestone
    issue_info['Status'] = status
    issue_info['LinkOfOriginal'] = links_org
    issue_info['Assigne'] = assigne
    issue_info['Reporter'] = reporter
    issue_info['Triage_Owner'] = triage_owner
    issue_info['Keywords'] = keywords
    issue_info['Whiteboard'] = whiteboard
    issue_info["BugID"] = issue_info["BugID"].str.extract("(\d*\.?\d+)", expand=True)
    issue_info['Product'] = issue_info['Product'].str.replace('[^a-zA-Z]', '')
    issue_info['Component'] = issue_info['Component'].str.replace('[^a-zA-Z]', '')
    component=[x.split('\n')[0] for x in component]
    issue_info['ComponentOrgName'] = component
    issue_info['LinkOfDuplicates'] = list_of_duplicates
    issue_info = issue_info.replace('\n', '', regex=True)
    issue_info['LinkOfDuplicates'] = issue_info['LinkOfDuplicates'].apply(
        lambda x: ','.join(x) if isinstance(x, list) else x)
    issue_info['LinkOfOriginal'] = issue_info['LinkOfOriginal'].apply(
        lambda x: ','.join(x) if isinstance(x, list) else x)
    issue_info['WhiteboardClean'] = whiteboard_details
    issue_info['BugFlag'] = bounty
    issue_info['FlagType'] = flag_value
    issue_info['TimeNLOpen'] = t_nl_open
    issue_info['TimeNLClose'] = t_nl_close
    issue_info['TrackingFlagsName'] = tracking_flag_name_all
    issue_info['TrackingFlagsTracking'] = tracking_flag_tracking_all
    issue_info['TrackingFlagsStatus'] = tracking_flag_status_all

    return issue_info, not_valid_ids


