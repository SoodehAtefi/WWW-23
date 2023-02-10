from HEADER import *
from data_analysis.statistics import *
df_Chromium=pd.read_csv('../datasets/Dataset_Chromium.csv')

# COMPONENTS=['Blink','Internals','Blink>JavaScript','UI','UI>Browser','Internals>Plugins','Internals>Plugins>PDF'
# ,'Platform','Internals>GPU','Internals>Skia']
# BROADS=['Memory buffer bounds error','Improper input validation','Resource management error','Expired pointer dereference'
# ,'Permission issues'
# ,'Numeric errors',
# 'Exposure of sensitive information',
# 'NULL pointer dereference',
# 'Improper access control',
# 'Race condition']
LIST_FEATURES= ['Releases','SecuritySeverity','Component','WeaknessType','Language']
######################################    Summary of dataset

print(df_Chromium.groupby('Releases')['ReportID'].count().reset_index(name = 'Count'))
print(df_Chromium.groupby('SecuritySeverity')['ReportID'].count().reset_index(name = 'Count'))
print(df_Chromium.groupby('IsExternal')['ReportID'].count().reset_index(name = 'Count'))
print('Number of Original Reports: ',len(df_Chromium[df_Chromium['PseudoID']==df_Chromium['ReportID']]))
print('Number of Duplicate Reports: ',len(df_Chromium[df_Chromium['PseudoID']!=df_Chromium['ReportID']]))

df_Chromium.groupby('Releases')['ReportID'].count().reset_index(name = 'Count').to_csv('../results/#ofReleasesChromium.csv',index=False)
df_Chromium.groupby('SecuritySeverity')['ReportID'].count().reset_index(name = 'Count').to_csv('../results//#ofSeverityChromium.csv',index=False)
df_Chromium.groupby('IsExternal')['ReportID'].count().reset_index(name = '#OfExternalReporters').to_csv('../results/#ofUniqueExternalReporterChromium.csv',index=False)


#####################################           Yealy Summary
num=df_Chromium.groupby('YearOpened')['ReportID'].count().reset_index(name= '#Reports')
num=num[num['YearOpened']>=2012].to_csv('../results/yearly_reports_Chromium.csv', index=False)

ex_in_yearly=df_Chromium.groupby(['YearOpened','IsExternal'])['ReportID'].nunique().reset_index(name = '#OfReports').to_csv('../results/yearly_ex_in_reports_Chromium.csv', index=False)

severity_yearly=df_Chromium.groupby(['YearOpened','SecuritySeverity'])['ReportID'].nunique().reset_index(name = '#OfReports').to_csv('../results/yearly_severity_reports_Chromium.csv', index=False)

releases_yearly=df_Chromium.groupby(['YearOpened','Releases'])['ReportID'].count().reset_index(name= '#OfReports').to_csv('../results/yearly_releases_reports_Chromium.csv', index=False)

original_yearly=df_Chromium[df_Chromium['PseudoID']==df_Chromium['ReportID']].groupby(['YearOpened'])['ReportID'].count().reset_index(name= '#OfOriginalReports').to_csv('../results/yearly_original_reports_Chromium.csv', index=False)
duplicate_yearly=df_Chromium[df_Chromium['PseudoID']!=df_Chromium['ReportID']].groupby(['YearOpened'])['ReportID'].count().reset_index(name= '#OfDuplicateReports').to_csv('../results/yearly_duplicate_reports_Chromium.csv', index=False)

#######################################       Internal versus external reports
for i in range(len(LIST_FEATURES)):
    print(LIST_FEATURES[i])
    df=pd.DataFrame()
    df=plot_stats(LIST_FEATURES[i],df_Chromium,'Chromium')
    df.to_csv('../results/Chrom_ie_' + str(LIST_FEATURES[i])+'.csv', index=False)
    Chi_Squared_Test(df['internals'].tolist(),df['externals'].tolist())

########################################      Internal versus external reports only based on Stable releases
#Internal versus external reports only based on stable releases
df_stable=df_Chromium[df_Chromium['Releases']=='Stable']
for i in range(len(LIST_FEATURES)):
    print(LIST_FEATURES[i])
    df=pd.DataFrame()
    df=plot_stats(LIST_FEATURES[i],df_stable,'Chromium')
    df.to_csv('../results/Chrom_ie_stable_' + str(LIST_FEATURES[i])+'.csv', index=False)
    Chi_Squared_Test(df['internals'].tolist(),df['externals'].tolist())
    print('\n')
########################################      Rediscovery ratios
#Rediscovery ratios
rediscovery_data=pd.DataFrame()
#remove same reporter that reports a vulnerability multiple time
rediscovery_data=df_Chromium.sort_values('Opened').drop_duplicates(subset=['PseudoIDRe', 'OriginalReporter'], keep='first')
for each in LIST_FEATURES:
    df = pd.DataFrame()
    df = redicovery_percentage(each, rediscovery_data,'Chromium')
    print(each, chisquare(df['Redicoveries'].tolist()))
    df.to_csv('../results/re_Chrom_' + str(each)+'.csv', index=False)
########################################      Probability that a vulnerability is not fixed in the 𝑡 days after it is first reported

not_fixed(df_Chromium).to_csv('../results/'+'not_fixed.csv', index = False)
not_fixed(df_Chromium[df_Chromium['Releases']=='Stable']).to_csv('../results/not_fixed_stable_Chromium.csv')
not_fixed(df_Chromium[(df_Chromium['Releases']!='Stable') & (~df_Chromium['Releases'].isna())]).to_csv('../results/not_fixed_dev_Chromium.csv')
########################################      Average time (days) to fix a vulnerability
for each in LIST_FEATURES:
    print(each)
    if each=='Releases':
        df_avg_patch_days=pd.DataFrame()
        df_avg_patch_days=df_Chromium[['ReportID','PseudoID','FixedTimestamp','Opened','TimeToFix','Releases']].copy()
        df_avg_patch_days.loc[((df_avg_patch_days['Releases']=='Beta') | (df_avg_patch_days['Releases']=='Head')),'Releases']='Dev'
        df=pd.DataFrame()
        df=avg_time_to_fix(df_avg_patch_days,'Releases','Chromium')
    else:
        df=pd.DataFrame()
        df=avg_time_to_fix(df_Chromium,each,'Chromium')
        # print(df)
    df.to_csv('../results/Avg_Patching_' + str(each)+'_Chrom'+'.csv', index=False)

########################################      Probability of rediscovery
#remove same reporter that reports a vulnerability multiple time
df_re=df_Chromium.sort_values('Opened').drop_duplicates(subset=['PseudoIDRe', 'OriginalReporter'], keep='first')
rediscovery(df_re).to_csv('../results/re_Chrom.csv',index=False)
rediscovery_week_interval(df_re[df_re['Releases']=='Stable']).to_csv('../results/re_Chrom_weekly_stable.csv',index=False)
rediscovery_week_interval(df_re[(df_re['Releases']!='Stable') & (~df_re['Releases'].isna())]).to_csv('../results/re_Chrom_weekly_not_stable.csv',index=False)
rediscovery_without_condition(df_re).to_csv('../results/re_Chrom_without_cond.csv',index=False)

########################################      Exploited versus not-exploited and Exploited versus external reports
for i in range(len(LIST_FEATURES)):
    df=pd.DataFrame()
    df=plot_stats_exploited(LIST_FEATURES[i],df_Chromium,'Chromium')
    df.to_csv('../results/Chrom_ie_exploited_other' + str(LIST_FEATURES[i])+'.csv', index=False)
    df_ex=plot_stats_exploited_versus_ex(LIST_FEATURES[i],df_Chromium,'Chromium')

    df_ex.to_csv('../results/Chrom_ie_exploited_externals' + str(LIST_FEATURES[i])+'.csv', index=False)
LIST_FEATURES=['Releases','SecuritySeverity','Component','WeaknessType','Language']

print('******************************************COMPARISON WITH OTHER*********************************************')
chi_square_results_exploited(plot_stats_exploited, df_Chromium,'all_other',LIST_FEATURES,'Chromium')
print('*************************************COMPARISON WITH EXTERNAL********************************************')
LIST_FEATURES=['Releases','SecuritySeverity','Language']# Component and BroadType did have enough data to do the test
chi_square_results_exploited(plot_stats_exploited_versus_ex, df_Chromium,'all_other_ex',LIST_FEATURES,'Chromium')

######################################         Number of Unique External Reporter
df_Chromium.loc[((df_Chromium['Releases']!='Stable') & (~df_Chromium['Releases'].isna())),'Releases']='Dev'
ex=df_Chromium[df_Chromium['IsExternal']==1]
ex.groupby('Releases')['OriginalReporter'].nunique().to_csv('../results/#UniqueExReporters.csv')