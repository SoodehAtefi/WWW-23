from HEADER import *
data_not_clean=pd.read_csv('../data/Firefox/collected_data_Firefox.csv', na_filter = False) # data
data_not_stable=pd.read_csv('../data/Firefox/stable_releases_Firefox.csv', na_filter = False)
print('Size of stable data:',len(data_not_stable))
print('Size of not clean data:',len(data_not_clean))
data_not_clean=data_not_clean.merge(data_not_stable, how = 'left', on='BugID')
# del data_not_clean['Unnamed: 0']
data_not_clean.loc[data_not_clean['FirstTimeOpened']=='NA','FirstTimeOpened']=-1
data_not_clean['FirstTimeOpened']=data_not_clean['FirstTimeOpened'].apply('int64')
data_not_clean['BugID']=data_not_clean['BugID'].apply('int64')
data_not_clean['PseudoID']=data_not_clean['PseudoID'].apply('int64')

#Filter out issues with 'INVALID' keword in their status
invalid_org_issues=data_not_clean[(data_not_clean['PseudoID']==data_not_clean['BugID']) & (~data_not_clean['Status'].str.contains('INVALID'))]
invalid_org_issues=invalid_org_issues.PseudoID.tolist()
invalid_org_issues=[str(x) for x in invalid_org_issues]
data_not_clean=data_not_clean[data_not_clean['PseudoID'].isin(invalid_org_issues)]

#Keep only 'defect' types
defect_type_issues = data_not_clean[(data_not_clean['PseudoID']==data_not_clean['BugID']) & (data_not_clean['Type']=='defect')]
defect_type_issues=defect_type_issues.PseudoID.tolist()
defect_type_issues=[str(x) for x in defect_type_issues]
data_not_clean=data_not_clean[data_not_clean['PseudoID'].isin(defect_type_issues)]

#Keep only core or Firefox original issues
core_Firefox = data_not_clean[(data_not_clean['PseudoID']==data_not_clean['BugID']) & ((data_not_clean['Product']=='Core') | (data_not_clean['Product']=='Firefox'))]
core_Firefox=core_Firefox.PseudoID.tolist()
core_Firefox=[str(x) for x in core_Firefox]
data_not_clean=data_not_clean[data_not_clean['PseudoID'].isin(core_Firefox)]

#Keep data opened in 2012 and after that
#Filter out issues opened before 2012
data_not_clean['YearOpened']=data_not_clean['TimeOpenend'].apply(lambda x:x.split('-')[0])
data_not_clean['YearOpened']=data_not_clean['YearOpened'].apply('int64')
data_before_2012=data_not_clean[(data_not_clean['YearOpened']<2012) & (data_not_clean['PseudoID']==data_not_clean['BugID'])]
orgs_before_2012=data_before_2012['PseudoID'].tolist()
orgs_before_2012=[str(x) for x in orgs_before_2012]
data_not_clean=data_not_clean[~data_not_clean['PseudoID'].isin(orgs_before_2012)]



#SEVERITY
def clean_severity(li):
    final = []
    for x in list_keyweords:
        if re.findall(str(x), li):
            final=li.split(',')
            break
    final = [x for x in final if 'sec-' in x]
    final = [x.split('sec-')[1] for x in final if 'sec-' in x]
    if len(final)==0:
        final = ['NA']
    return final

def dict_org_dups(data):
    IDs=data[['BugID','PseudoID']]
    b = IDs.groupby(by=['BugID','PseudoID']).agg('count')
    final_dict = {}
    for BugID, PseudoID in b.index:
        final_dict.setdefault(PseudoID,[]).append(BugID)
    return final_dict

# Filter out issues with 'wontfix', 'incomplete', and other invalid status
#There are issues that have 'WORKSFORME' or 'INCOMPLETE' in their status field but they are fixed in a version (shows in their Trackingflag field) which we do not remove them

issues_with_other_invalid_status=data_not_clean[(data_not_clean['PseudoID']==data_not_clean['BugID'])&(~data_not_clean['Status'].str.contains('DUPLICATE')) & (~data_not_clean['TrackingFlagsStatus'].str.contains('fixed')) & (~data_not_clean['Status'].str.contains('VERIFIED        FIXED        ')) & (~data_not_clean['Status'].str.contains('RESOLVED        FIXED        ')) & (~data_not_clean['Status'].str.contains('NEW')) & (~data_not_clean['Status'].str.contains('REOPENED')) & (~data_not_clean['Status'].str.contains('ASSIGNED'))]
issues_with_other_invalid_status=issues_with_other_invalid_status.PseudoID.tolist()
issues_with_other_invalid_status=[str(x) for x in issues_with_other_invalid_status]
data_not_clean=data_not_clean[~data_not_clean['PseudoID'].isin(issues_with_other_invalid_status)]


#Filter out issues that their original does not have any of the security keywords
issues_with_severity = data_not_clean[(data_not_clean['PseudoID']==data_not_clean['BugID']) & ((data_not_clean['Keywords'].str.contains('sec-critical'))|(data_not_clean['Keywords'].str.contains('sec-high'))|(data_not_clean['Keywords'].str.contains('sec-moderate'))|(data_not_clean['Keywords'].str.contains('sec-low'))|(data_not_clean['Keywords'].str.contains('sec-other'))|(data_not_clean['Keywords'].str.contains('sec-vector')))]
issues_with_severity=issues_with_severity.PseudoID.tolist()
issues_with_severity=[str(x) for x in issues_with_severity]
data_not_clean=data_not_clean[data_not_clean['PseudoID'].isin(issues_with_severity)]
print('size of data after filterings',len(data_not_clean))
print('#################Cleaning SEVERITY')
list_keyweords= ['sec-critical','sec-high', 'sec-moderate','sec-low','sec-other','sec-vector']
data_not_clean['Keywords_f']=data_not_clean['Keywords'].apply(lambda x:clean_severity(x))
final_dict = {}
final_dict =dict_org_dups(data_not_clean)
#dictionary each Id and its severity
dict_severity = {}
check =[]
for key,value in final_dict.items():
    for every_id in value:
        temp=(data_not_clean[(data_not_clean['BugID']==every_id)].Keywords_f.tolist())
        temp=[item for sublist in temp for item in sublist]
#         print(temp)
        if len(temp)>1:
            check.append(every_id)
        dict_severity[every_id]=temp

final_severity_dict = {}
for key,value in final_dict.items():
    final_list = []
    for each_bugid in value:
        if sorted(dict_severity[key])==sorted(dict_severity[each_bugid]):
            final_list.append(dict_severity[key])
        elif (sorted(dict_severity[key])!=sorted(dict_severity[each_bugid])) and (dict_severity[key][0]!='NA'):
            final_list.append(dict_severity[key])
        else:
            print(each_bugid)
    final_list=list(set([item for sublist in final_list for item in sublist]))

    final_severity_dict[key] = final_list

for key,value in final_severity_dict.items():
        value=','.join(value)
        data_not_clean.loc[data_not_clean['PseudoID']==key,'Criticality']=value
del data_not_clean['Keywords_f']
# data_not_clean.to_csv('../data/Firefox/data_to_collect_weakness_langs.csv')
print('#################Cleaning COMPONENTS')
#COMPONENT
final_dict = {}
final_dict = dict_org_dups(data_not_clean)

dict_components = {}
for key, value in final_dict.items():
    for every_id in value:
        temp = (data_not_clean[(data_not_clean['BugID'] == every_id)].Component.tolist())
        dict_components[every_id] = temp

final_component_dict = {}
for key, value in final_dict.items():
    final_list = []
    for each_bugid in value:

        if sorted(dict_components[key]) == sorted(dict_components[each_bugid]):
            final_list.append(dict_components[key])
        elif (sorted(dict_components[key]) != sorted(dict_components[each_bugid])) and (len(dict_components[key]) >= 1):
            final_list.append(dict_components[key])
        elif (sorted(dict_components[key]) != sorted(dict_components[each_bugid])) and (
                len(dict_components[key]) < 1) and (len(dict_components[each_bugid]) >= 1):
            final_list.append(dict_components[each_bugid])
        elif (sorted(dict_components[key]) != sorted(dict_components[each_bugid])):
            print('********************')
        else:
            print('pass', each_bugid)
    #             pass
    final_list = list(set([item for sublist in final_list for item in sublist]))
    final_component_dict[key] = final_list


for key, value in final_component_dict.items():
    data_not_clean.loc[data_not_clean['PseudoID'] == key, 'Component_final'] = value[0]
del data_not_clean['Component']
data_not_clean = data_not_clean.rename(columns={'Component_final': 'Component'})

print('#################Cleaning WEAKNESS TYPES')
#WEAKNESS TYPES
data_not_clean['CVE'] = data_not_clean['CVE'].replace(np.nan, 'NA')
data_not_clean['CVE'] = data_not_clean['CVE'].replace(to_replace='\(', value="", regex=True)
data_not_clean['CVE'] = data_not_clean['CVE'].replace(to_replace='\)', value="", regex=True)

final_dict = {}
final_dict = dict_org_dups(data_not_clean)

dict_cve = {}
for key, value in final_dict.items():
    for every_id in value:
        temp = (data_not_clean[(data_not_clean['BugID'] == every_id)].CVE.tolist())
        if 'CVE' not in temp[0]:
            temp = ['NA']
        dict_cve[every_id] = temp

final_cve_dict = {}
for key, value in final_dict.items():
    final_list = []
    for each_bugid in value:

        if sorted(dict_cve[key]) == sorted(dict_cve[each_bugid]):
            final_list.append(dict_cve[key])
        elif (sorted(dict_cve[key]) != sorted(dict_cve[each_bugid])) and (dict_cve[key][0] != 'NA'):
            final_list.append(dict_cve[key])
        elif (sorted(dict_cve[key]) != sorted(dict_cve[each_bugid])) and (dict_cve[key][0] == 'NA'):
            final_list.append(dict_cve[each_bugid])
        else:
            #             pass
            print(each_bugid)
    final_list = list(set([item for sublist in final_list for item in sublist]))
    if (len(final_list) > 1) & ('NA' in final_list):
        final_list = [x for x in final_list if x != 'NA']
    final_cve_dict[key] = final_list

for key, value in final_cve_dict.items():
    if len(value) > 1:
        print(key)
    data_not_clean.loc[data_not_clean['PseudoID'] == key, 'CVE_final'] = value[0]

cve_details = pd.read_csv('../data/Firefox/CVE_Details_Firefox.csv')

cve_details = cve_details.drop_duplicates(subset=['CVE_ID'], ignore_index=True)
cve_details = cve_details[['CVE_ID', 'CWE ID']]
cve_details.rename(columns={'CVE_ID': 'CVE_final', 'CWE ID': 'CWE'}, inplace=True)
data_not_clean = data_not_clean.merge(cve_details, on='CVE_final', how='left')

broad = pd.read_csv('../data/Firefox/CWE_with_Name_Firefox.csv')  # the same CWE with broadtype info file (updated after 15 sep)
broad['CWE'] = broad['CWE'].astype('str')
# broad=broad.rename(columns = {'CWE':'CWE'})
data_not_clean['CWE'] = data_not_clean['CWE'].astype('str')
data_not_clean = data_not_clean.merge(broad, on='CWE', how='left')
data_not_clean.loc[data_not_clean['CWE'] == 'nan', 'CWE'] = -1
data_not_clean.loc[data_not_clean['CWE'] == 'CWE id is not defined for this vulnerability', 'CWE'] = -1
data_not_clean.loc[data_not_clean['CWE'] == 'Webpage N/A', 'CWE'] = -1

data_not_clean[~data_not_clean['Broad_type'].isna()]
del data_not_clean['Name']
del data_not_clean['Broad_type_CWE']

print('#################Cleaning RELEASES')

data_not_clean.loc[data_not_clean['IsStable'] != 1, 'IsStable'] = 'NA'

dict_stable = {}
for key, value in final_dict.items():
    for every_id in value:
        temp = (data_not_clean[(data_not_clean['BugID'] == every_id)].IsStable.tolist())
        dict_stable[every_id] = temp

final_stable_dict = {}
for key, value in final_dict.items():
    final_list = []
    for each_bugid in value:

        if dict_stable[key] == dict_stable[each_bugid]:
            final_list.append(dict_stable[key])
        elif (dict_stable[key][0] != dict_stable[each_bugid][0]) and (dict_stable[key][0] != 'NA'):
            final_list.append(dict_stable[key])
        elif (sorted(dict_stable[key]) != sorted(dict_stable[each_bugid])) and (dict_stable[key][0] == 'NA'):
            final_list.append(dict_stable[each_bugid])
        else:
            #             pass
            print(each_bugid)
    final_list = list(set([item for sublist in final_list for item in sublist]))

    if (len(final_list) > 1) & ('NA' in final_list):
        final_list = [x for x in final_list if x != 'NA']

    final_stable_dict[key] = final_list

for key, value in final_stable_dict.items():
    if len(value) > 1:
        print(key)
    data_not_clean.loc[data_not_clean['PseudoID'] == key, 'Stable_final'] = value[0]
data_not_clean.loc[data_not_clean['Stable_final'] != 1, 'Stable_final'] = 0
print('Number of stable issues: ', len(data_not_clean[data_not_clean['Stable_final'] == 1]))
print('Number of not-stable issues: ', len(data_not_clean[data_not_clean['Stable_final'] == 0]))
del data_not_clean['IsStable']
data_not_clean = data_not_clean.rename(columns={'Stable_final': 'IsStable'})

orgsss = data_not_clean[data_not_clean['BugID'] == data_not_clean['PseudoID']]
# orgs=data_not_clean[data_not_clean['pseudoID']==data_not_clean['Bug_ID']]
Id_orgs = orgsss['BugID'].tolist()
data_not_clean[~data_not_clean['PseudoID'].isin(Id_orgs)]
orgs = data_not_clean[data_not_clean['PseudoID'] == data_not_clean['BugID']].BugID.tolist()
dups = data_not_clean[data_not_clean['PseudoID'] != data_not_clean['BugID']].BugID.tolist()
data_not_clean[(data_not_clean['IsStable'] == 0) & (data_not_clean['PseudoID'] == data_not_clean['BugID'])]

print('#################Cleaning LANGUAGES')
data_lang=pd.read_csv('../data/Firefox/Languages_Firefox.csv')
data_lang=data_lang.rename(columns = {'BugID':'PseudoID'})
data_not_clean=data_not_clean.merge(data_lang, on = 'PseudoID', how= 'left')
data_not_clean.loc[data_not_clean['Language'].isna(),'Language']='NA'

print('#################Cleaning FIXED TIME')
data_not_clean['Closed'] = data_not_clean['Closed'].apply('int64')
dict_fix = {}
for key, value in final_dict.items():
    temp = (data_not_clean[(data_not_clean['PseudoID'] == key) & (data_not_clean['StatusNow'] == 'Closed') &
                           ((data_not_clean['Status'] == 'VERIFIED        FIXED        ') |
                            (data_not_clean['Status'] == 'RESOLVED        FIXED        '))].Closed.tolist())
    if len(temp) == 0:
        temp = ['NA']
    dict_fix[key] = temp

for key, value in dict_fix.items():
    data_not_clean.loc[data_not_clean['PseudoID'] == key, 'FixedTimestamp'] = value[0]

data_not_clean.loc[data_not_clean['FixedTimestamp'] == 'NA', 'FixedTimestamp'] = -1
data_not_clean['FixedTimestamp'] = data_not_clean['FixedTimestamp'].apply('int64')

data_not_clean.loc[(data_not_clean['FixedTimestamp'] != -1), 'TimeToFix'] = (data_not_clean['FixedTimestamp'] -
                                                                             data_not_clean['FirstTimeOpened']) / (
                                                                                        3600 * 24)
data_not_clean.loc[(~data_not_clean['TimeToFix'].isna()), 'TimeToFix'] = data_not_clean['TimeToFix'].apply(
    lambda x: np.floor(x))

data_not_clean['TimeFromFirstReport'] = (data_not_clean['Opened'] - data_not_clean['FirstTimeOpened']) / (3600 * 24)
data_not_clean['TimeFromFirstReport'] = data_not_clean['TimeFromFirstReport'].apply(lambda x: np.floor(x))

data_not_clean.loc[data_not_clean['FirstTimeOpened'] == -1, 'TimeFromFirstReport'] = -1
data_not_clean.loc[data_not_clean['FirstTimeOpened'] == -1, 'TimeToFix'] = -1

data_not_clean.loc[data_not_clean['TimeToFix'].isna(), 'TimeToFix'] = -1

print('#################Cleaning EXPLOITED')
#from https://www.cisa.gov/known-exploited-vulnerabilities-catalog
#then search comments with different phrases to add to the above list
exploited=['CVE-2019-9810','CVE-2019-11708','CVE-2016-9079','CVE-2020-6819','CVE-2022-26485','CVE-2022-26486','CVE-2019-11707','CVE-2020-6820','CVE-2013-1670','CVE-2013-1690','CVE-2015-4495','CVE-2019-17026','CVE-2013-1675']

df_comments=pd.read_pickle("../data/Firefox/comments_Firefox.pkl")
df_comments['IsExploited']=(df_comments['Comments'].str.contains('exploited in the wild')) |(df_comments['Comments'].str.contains('exploited security vulnerability'))|(df_comments['Comments'].str.contains('exploit in the wild')) |(df_comments['Comments'].str.contains('exploits are in the wild'))|(df_comments['Comments'].str.contains('exploitable in the wild'))|(df_comments['Comments'].str.contains('exploitability in the wild'))|(df_comments['Comments'].str.contains('exploiting in wild'))|(df_comments['Comments'].str.contains('used in wild'))|(df_comments['Comments'].str.contains('used in the wild'))|(df_comments['Comments'].str.contains('used in a wild'))|(df_comments['Comments'].str.contains('out in the wild')) |(df_comments['Comments'].str.contains('occurring in the wild')) |(df_comments['Comments'].str.contains('occurring in-the-wild')) |(df_comments['Comments'].str.contains('occurs in the wild')) |(df_comments['Comments'].str.contains('happening in-the-wild')) |(df_comments['Comments'].str.contains('happening in the wild')) |(df_comments['Comments'].str.contains('abused in the wild')) |(df_comments['Comments'].str.contains('present in the wild')) |(df_comments['Comments'].str.contains('observed in the wild')) |(df_comments['Comments'].str.contains('already in the wild')) |(df_comments['Comments'].str.contains('seen in the wild')) |(df_comments['Comments'].str.contains('"in the wild"')) |(df_comments['Comments'].str.contains('in-the-wild')) |(df_comments['Comments'].str.contains('in wild')) |(df_comments['Comments'].str.contains('from the wild')) |(df_comments['Comments'].str.contains('zero day')) |(df_comments['Comments'].str.contains('zero-day')) | (df_comments['Summary'].str.contains('zero day')) | (df_comments['Summary'].str.contains('zero-day'))
df_comments['IsnotExploited']=(df_comments['Comments'].str.contains('happens in the wild'))| (df_comments['Comments'].str.contains('show up in the wild')) | (df_comments['Comments'].str.contains('test in the wild'))| (df_comments['Comments'].str.contains('enabled in the wild')) | (df_comments['Comments'].str.contains('crashes in the wild')) | (df_comments['Comments'].str.contains('reachable up in the wild')) | (df_comments['Comments'].str.contains('triggered in the wild')) | (df_comments['Comments'].str.contains('triggerable in the wild')) | (df_comments['Comments'].str.contains('manifest in the wild'))
df_exploited=df_comments[(df_comments['IsExploited']==True) & (df_comments['IsnotExploited']==False)]
df_exploited=df_exploited[['BugID','IsExploited']]

# exploited_subset=pd.read_csv('/Users/soodeh/PycharmProjects/Firefox_Study/data/Isexploited_Firefox.csv')
#from dataset find report id of the CVEs
exploited_ids=['1070638',' 1658881 ','1672223', '825697' ,'1043778', '929539', '854897','1172482','1758062']
#finally we manually check the comments and summary of the subset reports extracted (by snow-balling of the comments in 'data_collection/comments.py') to add to the list of exploited ids/reports
# final_exploited_reports=pd.read_csv('exploited_reports_Firefox.csv')
final_exploited_reports=['1672223', '1043778', '929539', '1559858', '866825', '1607443', '854897', '1537924', '1178058', '857883', '825697', '853709', '1758070', '1758062', '1626728', '1544386', '1321066', '1620818']

df_exploited=pd.DataFrame()
df_exploited['BugID']=[int(x) for x in final_exploited_reports]
df_exploited['IsExploited']=1
data_not_clean=data_not_clean.merge(df_exploited,on = 'BugID', how ='left')
data_not_clean.loc[data_not_clean['IsExploited']!=1, 'IsExploited']=0
exploiteds_remove_redundents=data_not_clean[data_not_clean['IsExploited']==1].drop_duplicates(subset = ['PseudoID'])
exploiteds_remove_redundents=exploiteds_remove_redundents.BugID.tolist()
exploiteds_remove_redundents=[str(x) for x in exploiteds_remove_redundents]
data_not_clean.loc[data_not_clean['BugID'].isin(exploiteds_remove_redundents), 'IsExploited']=1
data_not_clean.loc[data_not_clean['IsExploited'].isna(), 'IsExploited']=0

data_not_clean['IsExploited']=data_not_clean['IsExploited'].apply('int64')
print('#################Cleaning EXTERNAL VERSUS INTERNAL')
df_ex_in=pd.read_csv('../data/Firefox/Ex_In_Reports_Firefox.csv')
del df_ex_in['ReportersMFSA']
df_ex_in['IsExternal']=df_ex_in['IsExternal'].astype('int64')
data_not_clean=data_not_clean.merge(df_ex_in, on ='BugID', how = 'left')
# just added to have the exact names of components in the figures
com_new=pd.read_csv('../data/Firefox/component_org_names_Firefox.csv')
data_not_clean=data_not_clean.merge(com_new, on = 'BugID', how='left')

# data_not_clean.to_csv('../data/Firefox/data_pre_stats_Firefox.csv',index=False)