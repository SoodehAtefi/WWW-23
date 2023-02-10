from data_collection.URLS import *
from HEADER import *
from data_collection.MFSA import extract_ids, reporters_MFSA

firefox_MFSA_versions = pd.DataFrame()
versions_urls = []
versions = []
urls = []


for each_link in tqdm.tqdm(MFSA_FIREFOX):
    #     time.sleep(0.5 +  numpy.random.uniform(0,1))
    r = requests.get(each_link)
    data = r.text
    d_stables = BeautifulSoup(data, 'lxml')
    versions_urls.append(d_stables.select('.level-item a'))

versions_urls = list(chain.from_iterable(versions_urls))

for each_url in versions_urls:
    urls.append(each_url['href'])
    versions.append(each_url['data'])

firefox_MFSA_versions['Versions'] = versions
firefox_MFSA_versions['Urls'] = urls
firefox_MFSA_versions['Urls'] = "https://www.mozilla.org" + firefox_MFSA_versions['Urls']
#filter some pages
list_urls = firefox_MFSA_versions['Urls'].tolist()
not_working = ['https://www.mozilla.org/en-US/security/advisories/mfsa2013-103/','https://www.mozilla.org/en-US/security/advisories/mfsa2012-89/','https://www.mozilla.org/en-US/security/advisories/mfsa2012-34/','https://www.mozilla.org/en-US/security/advisories/mfsa2012-20/','https://www.mozilla.org/en-US/security/advisories/mfsa2012-11/','https://www.mozilla.org/en-US/security/advisories/mfsa2013-96/']
issues_2010_2011=[x for x in list_urls if '2010' or '2011' in x]
list_urls=[x for x in list_urls if x not in not_working and x not in issues_2010_2011]

df_final = pd.DataFrame()
df_final_lists = []
for each_url in tqdm.tqdm(list_urls):
    df_final_lists.append(reporters_MFSA(each_url))
df_f = pd.concat(df_final_lists)
df_f['extras']=df_f['url'].apply(lambda s: extract_ids(s))
df_f=df_f.explode('extras')
df_f=df_f.reset_index()


df_f.loc[(~df_f['extras'].isna()), 'BugID_2'] =df_f['extras']
df_f.loc[df_f['extras'].isna(),'BugID_2'] = df_f['BugID']

del df_f['BugID']
del df_f['extras']

df_f=df_f.rename(columns = {'BugID_2':'BugID'})
df_f=df_f[df_f['BugID']!=""]
df_f=df_f[df_f['url'].str.startswith('https://bugzilla.mozilla.org/')]
df_f['BugID']=df_f['BugID'].apply('int64')
df_f=df_f.drop_duplicates(subset =['BugID'])
df_f=df_f.reset_index()
del df_f['level_0']
del df_f['index']
# df_f.to_csv('../data/Firefox/MFSA_reporters_Firefox.csv', index = False)