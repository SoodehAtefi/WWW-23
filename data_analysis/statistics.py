from HEADER import *

def Chi_Squared_Test(d1,d2):
    data = [d1, d2]
    stat, p, dof, expected = chi2_contingency(data)
    alpha = 0.05
    if p <= alpha:
        print('-------------------------------------->Dependent (reject H0)')
        result = 'Dependent (reject H0)'
        print("p value is: " + str(p))
        print('dof: ',dof)
        print('\n')
        return p
    else:
        print('Independent (H0 holds true)')
        print("p value is: " + str(p))
        print('\n')
        
def chi_square_results_exploited(func,df_valid_issues,CompareWith,LIST_FEATURES,VRP):
    for i in range(len(LIST_FEATURES)):
        print(LIST_FEATURES[i])
        result_f= func(LIST_FEATURES[i], df_valid_issues,VRP)
        Chi_Squared_Test(result_f['exploited'].tolist(),result_f[CompareWith].tolist())
        print('\n')
        
#Internal versus external reports
def plot_stats(x, data,VRP):
    main_data = data[~data[x].isnull()]
    if (x == 'Component') & (VRP=='Chromium'):
        main_data = main_data[['ReportID', 'Component', 'IsExternal']]
        main_data['Component'] = main_data['Component'].apply(literal_eval)
        main_data = main_data.explode('Component')

    elif x == 'Language':

        main_data = main_data[['ReportID', 'Language', 'IsExternal']]
        main_data['Language'] = main_data['Language'].apply(literal_eval)
        main_data = main_data.explode('Language')
    else:
        pass

    data_feature = main_data.groupby(str(x))['ReportID'].count().reset_index(name='allIssues')

    external_main_data = main_data[main_data['IsExternal'] == 1]
    len_ex = external_main_data['ReportID'].nunique()

    internal_main_data = main_data[main_data['IsExternal'] == 0]
    len_in = internal_main_data['ReportID'].nunique()
    main_external_data = external_main_data.groupby(x)['ReportID'].count().reset_index(name='externals')
    main_internal_data = internal_main_data.groupby(x)['ReportID'].count().reset_index(name='internals')

    final_stable = data_feature.merge(main_internal_data, how='outer', on=str(x))
    final_stable = final_stable.merge(main_external_data, how='outer', on=str(x))

    final_stable['internals'] = final_stable['internals'].replace(np.nan, 0)
    final_stable['externals'] = final_stable['externals'].replace(np.nan, 0)

    final_stable['internalPercentage'] = (final_stable['internals'] / len_in) * 100
    final_stable['externalPercentage'] = (final_stable['externals'] / len_ex) * 100

#    if x == 'Component':
#        final_stable = final_stable[final_stable['Component'].isin(COMPONENTS)]
#    if x == 'BroadType':
#        final_stable = final_stable[final_stable['BroadType'].isin(BROADS)]
    
    return final_stable

#Rediscovery ratios
def redicovery_percentage(x, data,VRP):
    main_data = data[~data[x].isnull()]
    if x=='Component'  and VRP=='Chromium':
        main_data = main_data[['ReportID', 'Component', 'PseudoIDRe']]
        main_data['Component'] = main_data['Component'].apply(literal_eval)
        main_data = main_data.explode('Component')
    elif x == 'Language':

        main_data = main_data[['ReportID', 'Language', 'PseudoIDRe']]
        main_data['Language'] = main_data['Language'].apply(literal_eval)
        main_data = main_data.explode('Language')
    else:
        pass

    df_orgs = main_data.groupby(x)['PseudoIDRe'].nunique().reset_index(name='total_count')

    count_dups = main_data.groupby('PseudoIDRe')['ReportID'].nunique().reset_index(name='count')

    rediscoveries = count_dups[count_dups['count'] > 1]
    all_rediscoveries = rediscoveries['PseudoIDRe'].tolist()
    all_rediscoveries = [str(x) for x in all_rediscoveries]
    all_rediscoveries = list(set(all_rediscoveries))
    df_dups = main_data[main_data['PseudoIDRe'].isin(all_rediscoveries)]

    df_dups = df_dups.groupby(x)['PseudoIDRe'].nunique().reset_index(name='Redicoveries')

    df_final = df_orgs.merge(df_dups, on=x, how='left')
    df_final['re_percentage'] = df_final['Redicoveries'] / df_final['total_count'] * 100

    df_final['Redicoveries'] = df_final['Redicoveries'].replace(np.nan, 0)
    df_final['total_count'] = df_final['total_count'].replace(np.nan, 0)
    df_final['re_percentage'] = df_final['re_percentage'].replace(np.nan, 0)
#    if x == 'Component':
#        df_final = df_final[df_final['Component'].isin(COMPONENTS)]
#    if x == 'BroadType':
#        df_final = df_final[df_final['BroadType'].isin(BROADS)]

    return df_final

#Probability that a vulnerability is not fixed in the 𝑡 days after it is first reported
def not_fixed(df_fix_rel):
    df_fix = df_fix_rel[(df_fix_rel['Opened'] == df_fix_rel['FirstReported']) & (df_fix_rel['FixedTimestamp'] != -1) & (
                df_fix_rel['Opened'] <= df_fix_rel['FixedTimestamp']) & (df_fix_rel['TimeToFix'] > -1)]
    listOfNotFixed = []
    lenOfDays = 366
    for i in range(lenOfDays):
        listOfNotFixed.append(df_fix[(df_fix['TimeToFix'] > i)].TimeToFix.size)

    NumberOfIssues_notFixed = pd.DataFrame()
    NumberOfIssues_notFixed['Num_Of_Issues_Not_Fixed'] = listOfNotFixed
    len_unique_ids_fixed = df_fix['PseudoID'].nunique()
    NumberOfIssues_notFixed['Prob'] = (NumberOfIssues_notFixed['Num_Of_Issues_Not_Fixed'] / len_unique_ids_fixed)

    return NumberOfIssues_notFixed


def avg_time_to_fix(df, attr,VRP):
    df_final = pd.DataFrame()
    df = df[~df[attr].isna()]

    df_fix = df[(df['FixedTimestamp'] != -1) & (df['Opened'] <= df['FixedTimestamp']) & (df['TimeToFix'] > -1)]
    df_fix = df_fix.drop_duplicates(subset=['PseudoID'], keep='first')

    if (attr == 'Component') & (VRP=='Chromium'):
        df_fix['Component'] =df_fix['Component'].apply(literal_eval)
        df_fix = df_fix.explode('Component')
    elif attr == 'Language':
        df_fix['Language'] = df_fix['Language'].apply(literal_eval)
        df_fix = df_fix.explode('Language')
    else:
        pass
    df_final = df_fix.groupby(attr)['TimeToFix'].mean().reset_index(name='Avg')
    # if attr == 'Component':
    #     df_final = df_final[df_final['Component'].isin(COMPONENTS)]
    # if attr == 'BroadType':
    #     df_final = df_final[df_final['BroadType'].isin(BROADS)]

    return df_final

#Probability of rediscovery
def rediscovery(data):
    tdays = 100
    final_df = pd.DataFrame()
    d_both_org_dups = data[(data['FixedTimestamp'] != -1) & (data['Opened'] <= data['FixedTimestamp'])]
    for i in range(0, tdays):
        denom = d_both_org_dups[
            (d_both_org_dups['TimeToFix'] > i) & (d_both_org_dups['PseudoIDRe'] == d_both_org_dups['ReportID'])]
        list_org = denom.ReportID.tolist()
        list_org = [str(x) for x in list_org]
        nom = d_both_org_dups[(d_both_org_dups['PseudoIDRe'] != d_both_org_dups['ReportID']) & (
                    d_both_org_dups['TimeFromFirstReport'] == i) & (d_both_org_dups['PseudoIDRe'].isin(list_org))]
        final_df.at[i, 'Frequancy'] = len(nom)
        #         print(len(nom))
        final_df.at[i, 'Avg'] = (len(nom) / len(denom))
        final_df.at[i, 'Num_Orgs'] = len(denom)
        nom_prob = nom.drop_duplicates(subset=['PseudoIDRe'])
        final_df.at[i, 'Frequancy_Prob'] = len(nom_prob)
        #         print(len(nom_prob))
        final_df.at[i, 'Prob'] = (len(nom_prob) / len(denom))

    days = np.arange(0, 100)
    final_df['days'] = days
    return final_df


def rediscovery_without_condition(data):
    tdays = 100
    final_df = pd.DataFrame()
    d_both_org_dups = data[(data['FixedTimestamp'] != -1) & (data['Opened'] <= data['FixedTimestamp'])]
    for i in range(0, tdays):
        denom = d_both_org_dups[d_both_org_dups['PseudoIDRe'] == d_both_org_dups['ReportID']]
        list_org = denom.ReportID.tolist()
        list_org = [str(x) for x in list_org]
        nom = d_both_org_dups[(d_both_org_dups['PseudoIDRe'] != d_both_org_dups['ReportID']) & (
                    d_both_org_dups['TimeFromFirstReport'] == i) & (d_both_org_dups['PseudoIDRe'].isin(list_org))]
        final_df.at[i, 'Frequancy'] = len(nom)
        #         print(len(nom))
        final_df.at[i, 'Avg'] = (len(nom) / len(denom))
        final_df.at[i, 'Num_Orgs'] = len(denom)
        nom_prob = nom.drop_duplicates(subset=['PseudoIDRe'])
        final_df.at[i, 'Frequancy_Prob'] = len(nom_prob)
        #         print(len(nom_prob))
        final_df.at[i, 'Prob'] = (len(nom_prob) / len(denom))

    days = np.arange(0, 100)
    final_df['days'] = days
    #     print(final_df)
    return final_df



def rediscovery_week_interval(data):
    tdays = list(np.arange(6, 100, 7))
    final_df = pd.DataFrame()
    d_both_org_dups = data[(data['FixedTimestamp'] != -1) & (data['Opened'] <= data['FixedTimestamp'])]
    for i in tdays:
        denom = d_both_org_dups[
            (d_both_org_dups['TimeToFix'] > i) & (d_both_org_dups['PseudoIDRe'] == d_both_org_dups['ReportID'])]
        list_org = denom.ReportID.tolist()
        list_org = [str(x) for x in list_org]

        nom = d_both_org_dups[(d_both_org_dups['PseudoIDRe'] != d_both_org_dups['ReportID']) & (
            d_both_org_dups['PseudoIDRe'].isin(list_org)) & ((d_both_org_dups['TimeFromFirstReport'] <= i) & (
                    d_both_org_dups['TimeFromFirstReport'] >= i - 6))]
        final_df.at[i, 'Frequancy'] = len(nom)
        #         print(len(nom))
        final_df.at[i, 'Avg'] = (len(nom) / len(denom))
        final_df.at[i, 'Num_Orgs'] = len(denom)
        nom_prob = nom.drop_duplicates(subset=['PseudoIDRe'])
        final_df.at[i, 'Frequancy_Prob'] = len(nom_prob)
        #         print(len(nom_prob))
        final_df.at[i, 'Prob'] = (len(nom_prob) / len(denom))

    #     days=np.arange(0,100)
    final_df['days'] = tdays
    #     print(final_df)
    return final_df

#Exploited versus not-exploited reports
def plot_stats_exploited(x, data,VRP):
    main_data = data[~data[x].isnull()]
    if (x == 'Component') & (VRP=='Chromium'):

        main_data = main_data[['ReportID', 'Component', 'IsExternal', 'IsExploited']]
        main_data['Component'] = main_data['Component'].apply(literal_eval)
        main_data = main_data.explode('Component')
    elif x == 'Language':

        main_data = main_data[['ReportID', 'Language', 'IsExternal', 'IsExploited']]
        main_data['Language'] = main_data['Language'].apply(literal_eval)
        main_data = main_data.explode('Language')
    else:
        pass

    data_feature = main_data.groupby(str(x))['ReportID'].count().reset_index(name='count')

    exploited_main_data = main_data[main_data['IsExploited'] == 1]
    len_ex = exploited_main_data['ReportID'].nunique()
    #     len_ex=len(exploited_main_data)

    other_main_data = main_data[main_data['IsExploited'] == 0]
    len_other = other_main_data['ReportID'].nunique()
#    print((len_other))
    #     len_other=len(other_main_data)

    main_exploited_data = exploited_main_data.groupby(x)['ReportID'].count().reset_index(name='count')
    main_other_data = other_main_data.groupby(x)['ReportID'].count().reset_index(name='count')

    final_df = data_feature.merge(main_exploited_data, how='outer', on=str(x))
    final_df = final_df.merge(main_other_data, how='outer', on=str(x))

    final_df = final_df.rename(columns={"count_x": "allIssues", "count_y": "exploited", "count": "all_other"})

    final_df['exploited'] = final_df['exploited'].replace(np.nan, 0)
    final_df['all_other'] = final_df['all_other'].replace(np.nan, 0)

    final_df['otherPercentage'] = (final_df['all_other'] / len_other) * 100
    final_df['exploitedPercentage'] = (final_df['exploited'] / len_ex) * 100
    return final_df

# Exploited versus external reports
def plot_stats_exploited_versus_ex(x, data,VRP):
    main_data = data[~data[x].isnull()]
    if (x == 'Component')& (VRP=='Chromium'):

        main_data = main_data[['ReportID', 'Component', 'IsExternal', 'IsExploited']]
        main_data['Component'] = main_data['Component'].apply(literal_eval)
        main_data = main_data.explode('Component')
    elif x == 'Language':

        main_data = main_data[['ReportID', 'Language', 'IsExternal', 'IsExploited']]
        main_data['Language'] = main_data['Language'].apply(literal_eval)
        main_data = main_data.explode('Language')
    else:
        pass
    data_feature = main_data.groupby(str(x))['ReportID'].count().reset_index(name='count')

    exploited_main_data = main_data[main_data['IsExploited'] == 1]
    len_ex = exploited_main_data['ReportID'].nunique()
    #     len_ex=len(exploited_main_data)
#    print((len_ex))
    other_main_data = main_data[(main_data['IsExploited'] == 0) & (main_data['IsExternal'] == 1)]
    len_other = other_main_data['ReportID'].nunique()
    #     len_other=len(other_main_data)
#    print('len_other', (len_other))
    main_exploited_data = exploited_main_data.groupby(x)['ReportID'].count().reset_index(name='count')
    main_other_data = other_main_data.groupby(x)['ReportID'].count().reset_index(name='count')

    final_df = data_feature.merge(main_exploited_data, how='outer', on=str(x))
    final_df = final_df.merge(main_other_data, how='outer', on=str(x))

    final_df = final_df.rename(columns={"count_x": "allIssues", "count_y": "exploited", "count": "all_other_ex"})

    final_df['exploited'] = final_df['exploited'].replace(np.nan, 0)
    final_df['all_other_ex'] = final_df['all_other_ex'].replace(np.nan, 0)

    final_df['OtherExPercentage'] = (final_df['all_other_ex'] / len_other) * 100
    final_df['ExploitedPercentage'] = (final_df['exploited'] / len_ex) * 100

    return final_df
