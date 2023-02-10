from HEADER import *
from data_analysis.statistics import *

LIST_FEATURES= ['Releases','SecuritySeverity','Component','WeaknessType','Language']
df_Firefox=pd.read_csv('../datasets/Dataset_Firefox.csv')

######################################    Summary of dataset
print(df_Firefox.groupby('Releases')['ReportID'].count().reset_index(name = 'Count'))
print(df_Firefox.groupby('SecuritySeverity')['ReportID'].count().reset_index(name = 'Count'))
print(df_Firefox.groupby('IsExternal')['ReportID'].count().reset_index(name = 'Count'))
print('Number of Original Reports: ',len(df_Firefox[df_Firefox['PseudoID']==df_Firefox['ReportID']]))
print('Number of Duplicate Reports: ',len(df_Firefox[df_Firefox['PseudoID']!=df_Firefox['ReportID']]))

df_Firefox.groupby('Releases')['ReportID'].count().reset_index(name = 'Count').to_csv('../results/#ofReleasesFirefox.csv',index=False)
df_Firefox.groupby('SecuritySeverity')['ReportID'].count().reset_index(name = 'Count').to_csv('../results//#ofSeverityFirefox.csv',index=False)
df_Firefox.groupby('IsExternal')['ReportID'].count().reset_index(name = '#OfExternalReporters').to_csv('../results/#ofUniqueExternalReporter.csv',index=False)

#####################################           Yealy Summary
num=df_Firefox.groupby('YearOpened')['ReportID'].count().reset_index(name= '#Reports')
num=num[num['YearOpened']>=2012].to_csv('../results/yearly_reports_Firefox.csv', index=False)

ex_in_yearly=df_Firefox.groupby(['YearOpened','IsExternal'])['ReportID'].nunique().reset_index(name = '#OfReports')
ex_in_yearly=ex_in_yearly[ex_in_yearly['YearOpened']>=2012].to_csv('../results/yearly_ex_in_reports_Firefox.csv', index=False)

severity_yearly=df_Firefox.groupby(['YearOpened','SecuritySeverity'])['ReportID'].nunique().reset_index(name = '#OfReports')
severity_yearly=severity_yearly[severity_yearly['YearOpened']>=2012].to_csv('../results/yearly_severity_reports_Firefox.csv', index=False)

releases_yearly=df_Firefox.groupby(['YearOpened','Releases'])['ReportID'].count().reset_index(name= '#OfReports')
releases_yearly[releases_yearly['YearOpened']>=2012].to_csv('../results/yearly_releases_reports_Firefox.csv', index=False)

original_yearly=df_Firefox[df_Firefox['PseudoID']==df_Firefox['ReportID']].groupby(['YearOpened'])['ReportID'].count().reset_index(name= '#OfOriginalReports')
original_yearly[original_yearly['YearOpened']>=2012].to_csv('../results/yearly_original_reports_Firefox.csv', index=False)
duplicate_yearly=df_Firefox[df_Firefox['PseudoID']!=df_Firefox['ReportID']].groupby(['YearOpened'])['ReportID'].count().reset_index(name= '#OfDuplicateReports')
duplicate_yearly[duplicate_yearly['YearOpened']>=2012].to_csv('../results/yearly_duplicate_reports_Firefox.csv', index=False)

######################################         Number of Unique External Reporter
ex=df_Firefox[(df_Firefox['IsExternal']==1)]
ex=ex[ex['OriginalReporter']!='Anonymous']
ex.groupby('Releases')['OriginalReporter'].nunique().reset_index(name = '#OfExternalReporters').to_csv('../results/#ofUniqueExternalReporter.csv',index=False)
#######################################       Internal versus external reports
print('Internal versus external analysis')
for i in range(len(LIST_FEATURES)):
    print(LIST_FEATURES[i])
    df = pd.DataFrame()
    df = plot_stats(LIST_FEATURES[i], df_Firefox, 'Firefox')
    df.to_csv('../results/Firefox_ie_' + str(LIST_FEATURES[i]) + '.csv', index=False)
    Chi_Squared_Test(df['internals'].tolist(), df['externals'].tolist())

########################################      Internal versus external reports only based on Stable releases
print('Internal versus external reports only based on stable releases')
df_stable = df_Firefox[df_Firefox['Releases'] == 'Stable']
for i in range(len(LIST_FEATURES)):
    print(LIST_FEATURES[i])
    df = pd.DataFrame()
    df = plot_stats(LIST_FEATURES[i], df_stable, 'Firefox')
    df.to_csv('../results/Firefox_ie_stable_' + str(LIST_FEATURES[i]) + '.csv', index=False)
    Chi_Squared_Test(df['internals'].tolist(), df['externals'].tolist())
    print('\n')

########################################      Rediscovery ratios
data_re = pd.DataFrame()
# remove same reporter that reports a vulnerability multiple time
data_re = df_Firefox.sort_values('Opened').drop_duplicates(subset=['PseudoIDRe', 'Reporter'], keep='first')

# deal with reopens (remove all its org and its dups)
reopened_orgs = data_re[(data_re['IsReopened'] == 1)].PseudoIDRe.to_list()
reopened_orgs = list(set(reopened_orgs))
reopened_orgs = [str(x) for x in reopened_orgs]
data_re = data_re[~data_re['PseudoIDRe'].isin(reopened_orgs)]

print('Rediscovery ratios')

for each in LIST_FEATURES:
    df = pd.DataFrame()
    df = redicovery_percentage(each, data_re, 'Firefox')
    print(each, chisquare(df['Redicoveries'].tolist()))
    df.to_csv('../results/re_Firefox_' + str(each) + '.csv', index=False)

########################################      Probability of rediscovery

rediscovery(data_re).to_csv('../results/re_Firefox.csv',index=False)
rediscovery_without_condition(data_re).to_csv('../results/re_Firefox_NoCond.csv',index=False)
rediscovery_week_interval(data_re[data_re['Releases']=='Stable']).to_csv('../results/re_Firefox_Weekly_Stable.csv',index=False)
rediscovery_week_interval(data_re[data_re['Releases']=='NotStable']).to_csv('../results/re_Firefox_Weekly_NotStable.csv',index=False)
########################################      Probability that a vulnerability is not fixed in the 𝑡 days after it is first reported

not_fixed(df_Firefox).to_csv('../results/'+'not_fixed.csv', index = False)
not_fixed(df_Firefox[df_Firefox['Releases']=='Stable']).to_csv('../results/not_fixed_stable_Firefox.csv',index=False)
not_fixed(df_Firefox[(df_Firefox['Releases']=='NotStable') & (~df_Firefox['Releases'].isna())]).to_csv('../results/not_fixed_Notstable_Firefox.csv',index=False)
########################################      Average time (days) to fix a vulnerability
for each in LIST_FEATURES:
    df=pd.DataFrame()
    df=avg_time_to_fix(df_Firefox,each,'Firefox')
        # print(df)
    df.to_csv('../results/Avg_Patching_' + str(each)+'_Firefox'+'.csv', index=False)
########################################      Exploited versus not-exploited and Exploited versus external reports
for i in range(len(LIST_FEATURES)):
    df=pd.DataFrame()
    df=plot_stats_exploited(LIST_FEATURES[i],df_Firefox,'Firefox')
    df.to_csv('../results/Firefox_ie_exploited_other' + str(LIST_FEATURES[i])+'.csv', index=False)
    df_ex=plot_stats_exploited_versus_ex(LIST_FEATURES[i],df_Firefox,'Firefox')

    df_ex.to_csv('../results/Firefox_ie_exploited_externals' + str(LIST_FEATURES[i])+'.csv', index=False)

LIST_FEATURES=['Releases','SecuritySeverity','Component','WeaknessType','Language']
print('******************************************COMPARISON WITH OTHER*********************************************')
chi_square_results_exploited(plot_stats_exploited, df_Firefox,'all_other',LIST_FEATURES,'Firefox')
print('*************************************COMPARISON WITH EXTERNAL********************************************')
LIST_FEATURES=['Releases','SecuritySeverity']# Component, WeaknessType, adn Languages did have enough data to do the test
chi_square_results_exploited(plot_stats_exploited_versus_ex, df_Firefox,'all_other_ex',LIST_FEATURES,'Firefox')

##################################################################################################################################
