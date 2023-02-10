from HEADER import *
def timestamp_to_date(x):
    ts = int(x)
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S').split('-')[0]

#this creates a column with the earliest report as the original report (for rediscovery analysis)
def earliest_report_as_org(data):
    IDs=data[['LocalID','PseudoID']]
    counts = IDs.groupby(by=['LocalID','PseudoID']).agg('count')
    final_dict = {}
    for BugID, PseudoID in counts.index:
        final_dict.setdefault(PseudoID,[]).append(BugID)

    dict_rediscovery = {}
    for key,value in final_dict.items():
        new_key=[]
        for x in value :
            temp=data[(data['Opened']==data['FirstReported']) & (data['LocalID']==x)].LocalID.tolist()
            if len(temp)!=0:
                 new_key=temp

        new_value=value + [key]
        new_value =list(set(new_value))
        dict_rediscovery[new_key[0]]=new_value

    for key,value in dict_rediscovery.items():
            for each in value:
                data.loc[data['LocalID']==each,'PseudoID_re']=key
    data['PseudoID_re']=data['PseudoID_re'].apply('int64')
    return data


df_main=pd.read_csv('../data/Chromium/ISSUES.csv',low_memory=False)
print('Size of data',len(df_main))
components=pd.read_csv('../data/Chromium/COMP_GROUPS.csv')
print('Size of component',len(components))
impacts=pd.read_csv('../data/Chromium/SECURITY_IMPACT_CHANNELS.csv')
print('Size of impacts',len(impacts))

languages=pd.read_csv('../data/Chromium/Languages_Chrom.csv') # all are original issues
languages=languages.rename(columns = {'LocalID':'PseudoID'}) #becuase only originls have the link to git sources
#keep earliest one as PseudoID for rediscovery analysis
df_main = earliest_report_as_org(df_main)

#filter out invalids
invalids_main=df_main[(df_main['LocalID']==df_main['PseudoID']) & (df_main['IsValid']==0)].PseudoID.tolist()
invalids_main=[str(x) for x in invalids_main]
df_valid_issues=df_main[~df_main['PseudoID'].isin(invalids_main)]
print('Valids Reports',len(df_valid_issues))

#Add a column with the year a report is opened
df_valid_issues=df_valid_issues.assign(YearOpened = np.nan)
df_valid_issues['YearOpened']=df_valid_issues['Opened'].apply(lambda x: timestamp_to_date(x))

#Components

merge_components=df_main[['LocalID','PseudoID','IgnoreCG', 'IsValid','IsExternal','PseudoID_re','Opened','FirstReported','OriginalReporterEmail']]
df_components=components.merge(merge_components, on = 'LocalID', how ='left')

#filter out invalid components
invalids_comp=df_components[(df_components['IsValid']==0) & (df_components['LocalID']==df_components['PseudoID'])].PseudoID.tolist()
invalids_comp=list(set([str(x) for x in invalids_comp]))
df_components=df_components[~df_components['PseudoID'].isin(invalids_comp)]

#filter out IgnoreCG'==1
filter_CGs=df_components[df_components['IgnoreCG']==1].PseudoID.tolist()
filter_CGs=list(set([str(x) for x in filter_CGs]))
print('Reports with IgnoreCG', len(filter_CGs))
df_components=df_components[~df_components['PseudoID'].isin(filter_CGs)]
print(len(df_components))

#Severity
unclassifieds=df_valid_issues[(df_valid_issues['SecuritySeverity']=='Unclassified') & (df_valid_issues['LocalID']==df_valid_issues['PseudoID'])].PseudoID.tolist()
unclassifieds=list(set([str(x) for x in unclassifieds]))
df_severity=df_valid_issues[~df_valid_issues['PseudoID'].isin(unclassifieds)]

#Impacted Releases stable versus not stable
merge_to_impcats=df_main[['LocalID','PseudoID','IgnoreSIC', 'IsValid','IsExternal']]
impacts=impacts.merge(merge_to_impcats, on = 'LocalID',how='left')
#filter out invalids
invalids=impacts[(impacts['LocalID']==impacts['PseudoID']) & (impacts['IsValid']==0)].PseudoID.tolist()
invalids=[str(x) for x in invalids]
valid_impacts=impacts[~impacts['PseudoID'].isin(invalids)]
print('valids',len(valid_impacts))


invalid_release_channels=valid_impacts[valid_impacts['IgnoreSIC']==1].PseudoID.tolist()
invalid_release_channels=[str(x) for x in invalid_release_channels]
invalid_release_channels=list(set(invalid_release_channels))
print(len(invalid_release_channels))
valid_release_channels=valid_impacts[~valid_impacts['PseudoID'].isin(invalid_release_channels)]
print(len(valid_release_channels))

invalid_impacts=valid_release_channels[(valid_release_channels['LocalID']==valid_release_channels['PseudoID']) & (valid_release_channels['SecurityImpactChannel']=='Not Available')]
invalids_ims=invalid_impacts['LocalID'].tolist()
invalids_ims=[str(x) for x in invalids_ims]
valid_release_channels=valid_release_channels[~valid_release_channels['PseudoID'].isin(invalids_ims)]


more_than_one=valid_release_channels.groupby('PseudoID')['SecurityImpactChannel'].nunique().reset_index(name = 'count')
more_than_one=more_than_one[more_than_one['count']>1].PseudoID.tolist()
more_than_one=[str(x) for x in more_than_one]
#ignoring 51 issues that have more than one impact (# 51 original reports and 112 reports have more than two stables)
valid_release_channels=valid_release_channels[~valid_release_channels['PseudoID'].isin(more_than_one)]

print('size of impacted dataset',len(valid_release_channels))

#Merging with the main data
release_impacts=valid_release_channels[['LocalID','SecurityImpactChannel']]
df_valid_issues=df_valid_issues.merge(release_impacts, on = 'LocalID', how='left')


del df_valid_issues['SecuritySeverity']
severity=df_severity[['LocalID','SecuritySeverity']]
df_valid_issues=df_valid_issues.merge(severity, on = 'LocalID', how = 'left')

df_com=(df_components.groupby(['LocalID']).agg({'CompGroup': lambda x: x.tolist()}).reset_index())
df_valid_issues=df_valid_issues.merge(df_com, on ='LocalID', how = 'left')

df_valid_issues=df_valid_issues.merge(languages,on ='PseudoID', how = 'left' )

df_valid_issues['YearOpened']=df_valid_issues['YearOpened'].apply('int64')

#Exploited Reports
df_comments=pd.read_csv('../data/Chromium/COMMENTS_Chromium.csv')
issue_summary=df_valid_issues[['LocalID', 'Summary']]
df_comments=df_comments.merge(issue_summary, on = 'LocalID', how = 'left')
df_comments=df_comments.rename(columns = {'Content':'Comments'})
#we first use https://www.cisa.gov/known-exploited-vulnerabilities-catalog to get initial set of exploited reports
#Them manually check the comments and summary of the subset (107) reports extracted (by snow-balling of the comments in 'data_collection/comments.py') to add to the list of exploited ids/reports

df_comments['IsExploited']=(df_comments['Comments'].str.contains('exploited in the wild')) |(df_comments['Comments'].str.contains('exploited security vulnerability'))|(df_comments['Comments'].str.contains('exploit in the wild')) |(df_comments['Comments'].str.contains('exploits are in the wild'))|(df_comments['Comments'].str.contains('exploitable in the wild'))|(df_comments['Comments'].str.contains('exploitability in the wild'))|(df_comments['Comments'].str.contains('exploiting in wild'))|(df_comments['Comments'].str.contains('used in wild'))|(df_comments['Comments'].str.contains('used in the wild'))|(df_comments['Comments'].str.contains('used in a wild'))|(df_comments['Comments'].str.contains('out in the wild')) |(df_comments['Comments'].str.contains('occurring in the wild')) |(df_comments['Comments'].str.contains('occurring in-the-wild')) |(df_comments['Comments'].str.contains('occurs in the wild')) |(df_comments['Comments'].str.contains('happening in-the-wild')) |(df_comments['Comments'].str.contains('happening in the wild')) |(df_comments['Comments'].str.contains('abused in the wild')) |(df_comments['Comments'].str.contains('present in the wild')) |(df_comments['Comments'].str.contains('observed in the wild')) |(df_comments['Comments'].str.contains('already in the wild')) |(df_comments['Comments'].str.contains('seen in the wild')) |(df_comments['Comments'].str.contains('"in the wild"')) |(df_comments['Comments'].str.contains('in-the-wild')) |(df_comments['Comments'].str.contains('in wild')) |(df_comments['Comments'].str.contains('from the wild')) |(df_comments['Comments'].str.contains('zero day')) |(df_comments['Comments'].str.contains('zero-day')) | (df_comments['Summary'].str.contains('zero day')) | (df_comments['Summary'].str.contains('zero-day'))

df_comments['IsnotExploited']=(df_comments['Comments'].str.contains('happens in the wild'))| (df_comments['Comments'].str.contains('show up in the wild')) | (df_comments['Comments'].str.contains('test in the wild'))| (df_comments['Comments'].str.contains('enabled in the wild')) | (df_comments['Comments'].str.contains('crashes in the wild')) | (df_comments['Comments'].str.contains('reachable up in the wild')) | (df_comments['Comments'].str.contains('triggered in the wild')) | (df_comments['Comments'].str.contains('triggerable in the wild')) | (df_comments['Comments'].str.contains('manifest in the wild'))
df_exploited=df_comments[(df_comments['IsExploited']==True) & (df_comments['IsnotExploited']==False)]
df_exploited=df_exploited[['LocalID','IsExploited']]
df_exploited=df_exploited.drop_duplicates(subset=['LocalID'])
after_manual_check=['156712', '203586', '354279', '407341', '510850', '565760', '767000', '879938', '917897', '961413', '991568', '1019226', '1053604', '1143772', '1144368', '1216437', '1249962', '1251727', '1251787', '1263462', '1296150', '1315901']
df_valid_issues.loc[(df_valid_issues['LocalID'].isin(after_manual_check)),'IsExploited']=1
exploited_cves=['CVE-2011-1823', 'CVE-2016-1646', 'CVE-2016-5198','CVE-2017-5030','CVE-2017-5070','CVE-2018-17463','CVE-2018-17480','CVE-2018-6065','CVE-2019-13720','CVE-2019-5786','CVE-2019-5825','CVE-2020-15999','CVE-2020-16009','CVE-2020-16010','CVE-2020-16013','CVE-2020-16017','CVE-2020-6418','CVE-2020-6572','CVE-2021-21148','CVE-2021-21166','CVE-2021-21193','CVE-2021-21206','CVE-2021-21220','CVE-2021-21224','CVE-2021-30533','CVE-2021-30551','CVE-2021-30554','CVE-2021-30563','CVE-2021-30632','CVE-2021-30633','CVE-2021-37973','CVE-2021-37975','CVE-2021-37976','CVE-2021-38000','CVE-2021-38003','CVE-2021-39793','CVE-2021-4102','CVE-2022-0609','CVE-2022-1096','CVE-2022-1364','CVE-2022-2294','CVE-2022-2856','CVE-2022-3075']

df_valid_issues.loc[(df_valid_issues['CVE'].isin(exploited_cves)),'IsExploited']=1
exploiteds_remove_redundents=df_valid_issues[df_valid_issues['IsExploited']==1].drop_duplicates(subset = ['PseudoID'])
exploiteds_remove_redundents=exploiteds_remove_redundents.LocalID.tolist()
exploiteds_remove_redundents=[str(x) for x in exploiteds_remove_redundents]
del df_valid_issues['IsExploited']
df_valid_issues.loc[df_valid_issues['LocalID'].isin(exploiteds_remove_redundents), 'IsExploited']=1
df_valid_issues.loc[df_valid_issues['IsExploited'].isna(), 'IsExploited']=0
print('len exploited',len(df_valid_issues[df_valid_issues['IsExploited']==1]))

#Fix
df_fix_release=pd.read_csv('../data/Chromium/FIX_RELEASE.csv')
df_fix_release=df_fix_release.rename(columns = {'LocalID':'PseudoID'})
df_fix_release=df_valid_issues.merge(df_fix_release, on = 'PseudoID',how = 'left')


df_fix_release.loc[df_fix_release['FixedTimestamp'].isna(), 'FixedTimestamp']=-1

df_fix_release['FixedTimestamp']=df_fix_release['FixedTimestamp'].apply('int64')
df_fix_release['FirstReported']=df_fix_release['FirstReported'].apply('int64')
df_fix_release['Opened']=df_fix_release['Opened'].apply('int64')

ignore_ids=df_fix_release[df_fix_release['IgnoreMSAN']==1].PseudoID.tolist()
ignore_ids=[str(x) for x in ignore_ids]
df_fix_rel=df_fix_release[~df_fix_release['PseudoID'].isin(ignore_ids)]

df_fix_rel=df_fix_rel[['LocalID','FixedTimestamp']]
df_valid_issues=df_valid_issues.merge(df_fix_rel, on = 'LocalID',how = 'left')
df_valid_issues['FixedTimestamp']=df_valid_issues['FixedTimestamp'].apply('int64')

df_valid_issues.loc[(df_valid_issues['FixedTimestamp']==-9223372036854775808),'FixedTimestamp']=-1# because we remove ignoremsns for orgs in subset (df_fix_rel)



#to fix SettingWithCopyWarning

df_valid_issues=df_valid_issues.assign(TimeToFix = np.nan)
df_valid_issues=df_valid_issues.assign(TimeFromFirstReport = np.nan)

#time to fix

df_valid_issues.loc[df_valid_issues['FixedTimestamp']!=-1, 'TimeToFix'] = (df_valid_issues['FixedTimestamp']-df_valid_issues['FirstReported'])/(3600*24)
df_valid_issues.loc[(~df_valid_issues['TimeToFix'].isna()), 'TimeToFix'] =df_valid_issues['TimeToFix'].apply(lambda x:np.floor(x))

df_valid_issues['TimeFromFirstReport']=(df_valid_issues['Opened']-df_valid_issues['FirstReported'])/(3600*24)
df_valid_issues['TimeFromFirstReport']=df_valid_issues['TimeFromFirstReport'].apply(lambda x:np.floor(x))


df_valid_issues.loc[df_valid_issues['FixedTimestamp'].isna(), 'FixedTimestamp']=-1
df_valid_issues.loc[df_valid_issues['TimeToFix'].isna(), 'TimeToFix']=-1


df_valid_issues['FixedTimestamp']=df_valid_issues['FixedTimestamp'].astype('int64')
df_valid_issues['TimeToFix']=df_valid_issues['TimeToFix'].astype('int64')
df_valid_issues['FirstReported']=df_valid_issues['FirstReported'].astype('int64')
df_valid_issues['TimeFromFirstReport']=df_valid_issues['TimeFromFirstReport'].astype('int64')
df_valid_issues['IsExploited']=df_valid_issues['IsExploited'].astype('int64')

Dataset_Chromium = df_valid_issues.rename(columns = {'LocalID':'ReportID','OriginalReporterEmail':'OriginalReporter','ReporterEmail':'Reporter','BugStatus':'Status','CompGroup':'Component','SecurityImpactChannel':'Releases','Broad_type':'WeaknessType','PseudoID_re':'PseudoIDRe'})
col_names=['PseudoID','PseudoIDRe','ReportID','Opened','Closed','YearOpened','Summary','OriginalReporter','Reporter','Status','SecuritySeverity',
 'Component','WeaknessType','IsExternal',
 'Releases','Language','IsExploited','FirstReported','FixedTimestamp','TimeToFix','TimeFromFirstReport']
Dataset_Chromium=Dataset_Chromium[col_names]
Dataset_Chromium=Dataset_Chromium.assign(IsReopened = np.nan)


# Dataset_Chromium.to_csv('../datasets/Dataset_Chromium.csv', index= False)