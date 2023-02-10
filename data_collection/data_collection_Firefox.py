from data_collection.info_extraction import *
from data_collection.KEYWORDS import *
from data_collection.URLS import *
from HEADER import *


def urls_basedon_keywords(keywords,first_part_url,second_part_url):
    links_all=[]
    for keyword in tqdm.tqdm(keywords):
        print('Keyword: ',keyword)
        #url2 = url_main + '&' +'keywords' + '=' + url
        url2 = first_part_url + keyword +second_part_url
        if (requests.get(url2)):
            time.sleep( 1.0 +  numpy.random.uniform(0,1))
            r = requests.get(url2)
            data = r.text
            soup=BeautifulSoup(data,"lxml")
            table_links = soup.find('table', class_='bz_buglist sortable')
            table_rows = table_links.find_all('tr')
            print('number of ', len(table_rows))
            for tr in table_rows:
                links_all.append(tr.find('a', href = re.compile(r'[/]([a-z]|[A-Z])\w+')).attrs['href'])
    links_all =['https://bugzilla.mozilla.org'+str(x) for x in links_all]
    links_all =[x for x in links_all if 'https://bugzilla.mozilla.org/buglist.cgi?' not in x]
    return links_all

def get_duplicates(df, dups_in_recursive,with_out_dups):
    list_of_dups = []
    for index,row in df.iterrows():
        if row['LinkOfDuplicates']!='NA':
            list_of_dups+=row['LinkOfDuplicates'].split(",")
            dups_in_recursive = dups_in_recursive.append(row,ignore_index=True)
        else:
            with_out_dups=with_out_dups.append(row,ignore_index=True)
    return list(set(list_of_dups)),dups_in_recursive,with_out_dups


def get_originals(df, main_originals, org_in_recuresive):
    list_of_org_in_rec = []
    for index, row in df.iterrows():
        if (row['LinkOfOriginal'] != 'NA'):
            list_of_org_in_rec.append(str(row['LinkOfOriginal']))
            org_in_recuresive = org_in_recuresive.append(row, ignore_index=True)
        else:
            main_originals = main_originals.append(row, ignore_index=True)
    return main_originals, org_in_recuresive, list(set(list_of_org_in_rec))



links_of_all_issues=urls_basedon_keywords(SECURITY_KEYWORDS,FIRST_PART_URL,SECOND_PART_URL)
data_df=pd.DataFrame()
data_df,_= extracter(links_of_all_issues)
data =data_df
data=data.drop_duplicates(subset = ['BugID'])

#get originals
df = data.reset_index()
list_of_org_in_rec = []
main_originals = pd.DataFrame()
org_in_recuresive = pd.DataFrame()
df_inaccessible_issues = pd.DataFrame()
main_originals,org_in_recuresive,list_of_org_in_rec=get_originals(df,main_originals,org_in_recuresive)
print(len(org_in_recuresive))
print(len(main_originals))
while len(list_of_org_in_rec)!=0:
    df,invalids=extracter(list_of_org_in_rec)
    df_inaccessible_issues=df_inaccessible_issues.append(invalids,ignore_index=True)
    main_originals,org_in_recuresive,list_of_org_in_rec=get_originals(df,main_originals,org_in_recuresive)

org_in_recuresive['BugID']=org_in_recuresive['BugID'].apply('int64')
main_originals['BugID']=main_originals['BugID'].apply('int64')
org_in_recuresive=org_in_recuresive.drop_duplicates(subset = ['BugID'])
main_originals=main_originals.drop_duplicates(subset = ['BugID'])

orgs = [main_originals,org_in_recuresive]
orgs_df = pd.DataFrame()
orgs_df=pd.concat(orgs,ignore_index=True)

orgs_df=orgs_df.drop_duplicates(subset = ['BugID'], keep = 'first')
orgs_df['BugID']=orgs_df['BugID'].astype('int64')

data=pd.concat([data,orgs_df])
data=data.drop_duplicates(subset = ['BugID'])

#get duplicates
df = data.reset_index()
list_of_dups = []
dups_in_recursive = pd.DataFrame()
with_out_dups = pd.DataFrame()
list_of_dups, dups_in_recursive, with_out_dups = get_duplicates(df, dups_in_recursive, with_out_dups)
while len(list_of_dups) != 0:
    df, invalids = extracter(list_of_dups)
    df_inaccessible_issues = df_inaccessible_issues.append(invalids, ignore_index=True)
    list_of_dups, dups_in_recursive, with_out_dups = get_duplicates(df, dups_in_recursive, with_out_dups)
    list_of_dups = list(set(list_of_dups))

    df_temp = pd.concat([dups_in_recursive, with_out_dups])
    list_of_dups_temp = [ele.split('https://bugzilla.mozilla.org/show_bug.cgi?id=')[1] for ele in list_of_dups]
    df_temp['BugID'] = df_temp['BugID'].astype(str)
    df_temp['BugID'] = df_temp['BugID'].apply(lambda x: x.split(".")[0])
    df_temp = df_temp.drop_duplicates(subset=['BugID'], keep='first', ignore_index=True)
    redundant_rows = df_temp[df_temp['BugID'].isin(list_of_dups_temp)]
    if (redundant_rows.empty == False) & (len(list_of_dups) == len(redundant_rows)):
        break

dups = pd.DataFrame()
dups_in_recursive=dups_in_recursive.drop_duplicates(subset = ['BugID'])
with_out_dups=with_out_dups.drop_duplicates(subset = ['BugID'])
twodfs =[with_out_dups,dups_in_recursive]
dups=pd.concat(twodfs,ignore_index=True)
dups= dups.drop_duplicates(subset = ['BugID'],keep = 'first')
dups['BugID']=dups['BugID'].astype('int64')

#merge final Data
df = pd.DataFrame()
final_d = [dups,data]
df  = pd.concat(final_d,ignore_index=True )
df['BugID']=df['BugID'].astype('int64')
df=df.drop_duplicates(subset = ['BugID'])

#one issue does not have close time ('1321567') which 'coerce' will put NA instead
df['Closed'] = pd.to_numeric(df['Closed'],errors='coerce')
df['Closed']=df['Closed'].apply('int64')
df['Opened']=df['Opened'].apply('int64')

#get all issue ids in the information fields of issues
all_ids_in_each_row =[]
for index,row in df.iterrows():
    li_all_ids=[]
    list_t=[]
    li_all_ids.append(str(row['BugID']))
    if row['LinkOfDuplicates']!='NA':
        li_all_ids+=row['LinkOfDuplicates'].split(",")
    if (row['LinkOfOriginal']!='NA') :
        li_all_ids.append(row['LinkOfOriginal'])
    if (row['LinkOfDuplicates']=='NA') & (row['LinkOfOriginal']=='NA'):
        li_all_ids.append(str(row['BugID']))
    list_t=list(map(lambda sub:int(''.join([ele for ele in sub if ele.isnumeric()])), li_all_ids))
    all_ids_in_each_row.append(list_t)

#make list of lists of those that are for the different reports of the same vulnerability
flat_ids = list(set(itertools.chain.from_iterable(all_ids_in_each_row)))
for each in flat_ids:
    subsets= [x for x in all_ids_in_each_row if each in x]
    for i in subsets:
        all_ids_in_each_row.remove(i)
    all_ids_in_each_row += [list(set(itertools.chain.from_iterable(subsets)))]

inaccessible_issues=df_inaccessible_issues[0].tolist()
inaccessible_issues=list(map(lambda sub:int(''.join([ele for ele in sub if ele.isnumeric()])), inaccessible_issues))
inaccessible_issues=list(set(inaccessible_issues))

#removing those duplicates that their originals do not have accessible links (remove all)
inaccessible_orgs=[]
for each_li in all_ids_in_each_row:
    for each_id in each_li:
        if len(df[(df['BugID']==each_id) & (df['Status'].str.contains('DUPLICATE'))])==1:
            #if its original do not have accessible link
            li_org=df[(df['BugID']==each_id)].LinkOfOriginal.tolist()
            li_org=list(map(lambda sub:int(''.join([ele for ele in sub if ele.isnumeric()])), li_org))
            if (li_org[0] in inaccessible_issues) :
                    index_to_remove=all_ids_in_each_row.index(each_li)
                    all_ids_in_each_row.pop(index_to_remove)
                    inaccessible_orgs.append(each_li)
                    break

all_ids_in_each_row2=[]
#get list of all issues that have same org but some dups are inaccessible so we can put 'NA' for first time opened
inaccessible_dups =[]
for each_li in all_ids_in_each_row:
    new_li = []
    for each_id in each_li:
        if each_id not in inaccessible_issues:
            new_li.append(each_id)
        else:
            inaccessible_dups.append(each_li)
    all_ids_in_each_row2.append(new_li)

inaccessible_orgs=list(set([ele for sublist in inaccessible_orgs for ele in sublist]))
inaccessible_dups=list(set([ele for sublist in inaccessible_dups for ele in sublist]))

#dictionary that has the original report as a key and its duplicates as a value
dict_org_dups = {}
for each_li in all_ids_in_each_row2:
    original_id=[]
    for each_id in each_li:
        original_id.append(df[(df['BugID']==each_id) & (~df['Status'].str.contains('DUPLICATE'))].BugID.tolist())
    original_id=[x for x in original_id if x]
    original_id= [ele for sublist in original_id for ele in sublist]
    if len(original_id)>=2:
        print('Issue has two originals or sth is wrong')
        break
    dict_org_dups[original_id[0]]=each_li

#dictionary that has earliest report as a key and later reports as a values
dict_earliest_report = {}
for each_li in all_ids_in_each_row2:
    opened_timestamps = []
    for each_id in each_li:
        opened_timestamps.append(df[df['BugID']==each_id].Opened.tolist()[0])
    opened_timestamps=[int(x) for x in opened_timestamps]
    #get the earliest report as key of dictionary
    earliest_open_time=min(opened_timestamps)
    earliest_report=df[df['Opened']==(earliest_open_time)].Opened.tolist()[0]
    dict_earliest_report[earliest_report] = each_li

#add two new columns to the dataframe FirstTimeOpened and PseudoID
#put open time of the earliest report as first time a vulnerability is reported
for key,value in dict_earliest_report.items():
    for x in value:
        df.loc[df['BugID']==x,'FirstTimeOpened']=key

for key,value in dict_org_dups.items():
    for x in value:
         df.loc[df['BugID']==x,'PseudoID']=key

df['FirstTimeOpened']=df['FirstTimeOpened'].apply('int64')
df['PseudoID']=df['PseudoID'].apply('int64')
df.loc[df['BugID'].isin(inaccessible_dups), 'FirstTimeOpened'] ='NA'
#inaccessible_orgs=[str(x) for x in inaccessible_orgs]
#remove those duplicates that their original is not accessible
df=df[~df['BugID'].isin(inaccessible_orgs)]

#uncomment to save the results
# df.to_csv('../data/Firefox/collected_data_Firefox.csv')


