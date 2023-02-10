from HEADER import *


def earliest_report_as_org(data):
    IDs=data[['BugID','PseudoID']]
    count_dups = IDs.groupby(by=['BugID','PseudoID']).agg('count')
    final_dict = {}
    for BugID, PseudoID in count_dups.index:
        final_dict.setdefault(PseudoID,[]).append(BugID)
    dict_rediscovery = {}
    for key,value in final_dict.items():
        new_key=[]
        for x in value :
            temp=data[(data['Opened']==data['FirstTimeOpened']) & (data['BugID']==x)].BugID.tolist()
            if len(temp)!=0:
                 new_key=temp
        new_value=value + [key]
        new_value =list(set(new_value))
        dict_rediscovery[new_key[0]]=new_value
    for key,value in dict_rediscovery.items():
            for each in value:
                data.loc[data['BugID']==each,'PseudoID_re']=key
    data['PseudoID_re']=data['PseudoID_re'].apply('int64')

    return data

def clean_status(element):
    element=element.replace('        ', ' ')
    element=element.strip()
    if 'of bug ' in element:
        element=element.split('of bug ')[0]
        element=element.strip()
    return element

df_Firefox=pd.read_csv('../data/Firefox/data_pre_stats_Firefox.csv')
df_Firefox.loc[df_Firefox['Broad_type']=='', 'Broad_type']=np.nan

del df_Firefox['Component']
df_Firefox=df_Firefox.rename(columns ={ 'ComponentOrgName':'Component'})
del df_Firefox['CVE']
df_Firefox=df_Firefox.rename(columns ={ 'CVE_final':'CVE'})
df_Firefox.loc[(df_Firefox['IsStable']==1),'IsStable']='Stable'
df_Firefox.loc[(df_Firefox['IsStable']==0),'IsStable']='NotStable'


all_criticalities=df_Firefox[(df_Firefox['Criticality']=='low') | (df_Firefox['Criticality']=='high')|(df_Firefox['Criticality']=='critical')|(df_Firefox['Criticality']=='moderate')]
all_criticalities=all_criticalities[['BugID','Criticality']]
del df_Firefox['Criticality']
df_Firefox=df_Firefox.merge(all_criticalities,on = 'BugID', how= 'left')
df_Firefox.loc[df_Firefox['Criticality']=='low','Criticality']='Low'
df_Firefox.loc[df_Firefox['Criticality']=='high','Criticality']='High'
df_Firefox.loc[df_Firefox['Criticality']=='critical','Criticality']='Critical'
df_Firefox.loc[df_Firefox['Criticality']=='moderate','Criticality']='Moderate'

df_have_earliest=df_Firefox[df_Firefox['FirstTimeOpened']!=-1].copy()
df_earliest_org=pd.DataFrame()
df_earliest_org=earliest_report_as_org(df_have_earliest)
df_earliest_org=df_earliest_org[['BugID','PseudoID_re']]
df_Firefox=df_Firefox.merge(df_earliest_org, on = 'BugID', how = 'left')

df_Firefox.loc[(df_Firefox['PseudoID_re'].isna()),'PseudoID_re']=-1
df_Firefox['PseudoID_re']=df_Firefox['PseudoID_re'].astype('int64')

################adding reopened reports identifier to the dataset
reopens=pd.read_csv('../data/Firefox/issues_reopened_Firefox.csv')
del reopens['NumberOfComments']
del reopens['Unnamed: 0']
reopens['Reopened']=1
reopens=reopens.drop_duplicates(subset = ['BugID'])
df_Firefox=df_Firefox.merge(reopens, on = 'BugID', how = 'left')
df_Firefox.loc[df_Firefox['Reopened'].isna(),'Reopened']=0

df_Firefox['Status']=df_Firefox['Status'].apply(clean_status)

df_Firefox=df_Firefox.rename(columns = {'PseudoID_re':'PseudoIDRe','BugID':'ReportID','Criticality':'SecuritySeverity','Reopened':'IsReopened','Broad_type':'WeaknessType','IsStable':'Releases','FirstTimeOpened':'FirstReported','Reopened':'IsReopened'})

df_Firefox['TimeFromFirstReport']=df_Firefox['TimeFromFirstReport'].apply('int64')
df_Firefox['TimeToFix']=df_Firefox['TimeToFix'].apply('int64')
df_Firefox['IsReopened']=df_Firefox['IsReopened'].apply('int64')

col_names=['PseudoID','PseudoIDRe','ReportID','Opened','Closed','YearOpened','Summary','OriginalReporter','Reporter','Status','SecuritySeverity','Component','WeaknessType','IsExternal','Releases','Language','IsExploited','FirstReported','FixedTimestamp','TimeToFix','TimeFromFirstReport','IsReopened']
Dataset_Firefox=pd.DataFrame()
Dataset_Firefox=df_Firefox[col_names]

# Dataset_Firefox.to_csv('../datasets/Dataset_Firefox.csv',index=False)
