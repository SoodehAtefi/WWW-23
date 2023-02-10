from HEADER import *


#Extract modified source files of issues (checking in comments)
def get_modified_files(url):
    req = requests.get(url)
    d_comments = req.text
    soup = BeautifulSoup(d_comments, "lxml")
    date = []
    if soup.find('td', class_='throw_error'):
        print("url is not available", url)
    else:
        all_comments = soup.findAll('div', class_='change-set')
        bug_all_info = soup.findAll('span', class_='bug-time-label')
        date = []
        for each_bug in bug_all_info:
            d_date = each_bug.find('span', class_='rel-time')
            date.append(d_date['data-time'])

    c_after_fixing_issue = []
    for i in range(len(all_comments)):
        if all_comments[i].find('span', class_='rel-time')['data-time'] == date[1]:
            c_after_fixing_issue = all_comments[i:]

    contain_urls_languages = []
    for each in c_after_fixing_issue:
        if each.find('div', class_='comment-text markdown-body') or each.find('pre', class_='comment-text'):
            if each.find('div', class_='comment-text markdown-body'):
                d_links = each.find('div', class_='comment-text markdown-body')
            if each.find('pre', class_='comment-text'):
                d_links = each.find('pre', class_='comment-text')
            links = d_links.findAll('a')
            for x in links:
                contain_urls_languages.append(x['href'])
    contain_urls_languages = list(set(contain_urls_languages))
    contain_urls_languages = [x for x in contain_urls_languages if (x.startswith('http'))]
    return contain_urls_languages
#Extract urls in the opened source links to get the file extensions
def get_urls_with_suffix_langs(main_url):
    final_urls=[]
    req_ = requests.get(main_url)
#     time.sleep( 0.2 +  np.random.uniform(0,1))
    data_sources = req_.text
    soup=BeautifulSoup(data_sources,"lxml")
    links_data = soup.findAll('div', class_ = 'title_text')
    for x in links_data[1:]: #the first 'title_text' is for first paragraph the second one is whether files are listed
        links_ =x.findAll('a', class_ ='list')
        for x in links_:
            final_urls.append(x['href'])
    return final_urls

#Collection
data=pd.read_csv('../data/Firefox/data_to_collect_weakness_langs.csv')

#Searching for issues that have been fixed (to get their modified source files)
data_modified_files=data[(data['Status']=='VERIFIED        FIXED        ') | (data['Status']=='RESOLVED        FIXED        ')]
list_of_fixed_and_released = data_modified_files['BugID'].tolist()
print(len(list_of_fixed_and_released))


source_links = {}
for url_m in tqdm.tqdm(list_of_fixed_and_released):
    url='https://bugzilla.mozilla.org/show_bug.cgi?id='+ str(url_m)
    res=get_modified_files(url)
    source_links[url_m]= res


source_links_clean={}
for key,value in source_links.items():
    temp=[x for x in value if ('https://hg.mozilla.org/') in x or ('http://hg.mozilla.org/') in x ]
    temp = list(set(temp))
    source_links_clean[key]=temp

source_links_clean_={key:[x.replace(' https', 'https') for x in value]  for (key,value) in source_links_clean.items() }
final_source_urls={}
for key,value in source_links_clean_.items():
    if len(value)!=0:
        final_source_urls[key]=value

dic_files_extensions={}
for key,value in tqdm.tqdm(final_source_urls.items()):
    all_links_per_issue = []
    for x in value:
        all_links_per_issue.append(get_urls_with_suffix_langs(x))
    dic_files_extensions[key]=all_links_per_issue


# with open('../data/Firefox/firefox_lang_suffix.pickle', 'wb') as handle:
#     pickle.dump(dic_lang_suffix, handle)

# file = open('../data/Firefox/firefox_lang_suffix.pickle', 'rb')
# dic_lang_suffix = pickle.load(file)
extensions_per_issue= {}
for key,value in dic_files_extensions.items():
        new_li = [item for items in value for item in items]
        list_of_langs =[x.split('.')[1] for x in new_li if '.' in x]
        list_of_langs=list(set(list_of_langs))
        extensions_per_issue[key]=list_of_langs

# with open('../data/Firefox/firefox_final_lang_suffixes.pickle', 'wb') as handle:
#     pickle.dump(extensions_per_issue, handle)

#Cleaning Languages to be able to merge to the main data
#Valid languages are cleaned manually
langs=['m4', 'js','xml','cc','css','cpp','py','xhtml','html','c','php','java','xsl','htm','pl','asm','jsm','cxx','pm','el','sjs','scss']
new_lang_dict={}
for key,value in extensions_per_issue.items():
    temp =[]
    for x in value:
        if x in langs:
            temp.append(x)
    new_lang_dict[key]=temp
merge_same_langs = {}
for key, value in new_lang_dict.items():
    temp = []
    for ele in value:
        if ele == 'cxx' or ele == 'cc':
            temp.append('cpp')
        elif ele == 'sjs' or ele == 'jsm':
            temp.append('js')

        elif ele == 'htm' or ele == 'xhtml':
            temp.append('html')
        elif ele == 'sass':
            temp.append('scss')

        else:
            temp.append(ele)

    temp = list(set(temp))
    merge_same_langs[key] = temp

#186 source files were empty after filtering 3686-186 = 3500

df=pd.DataFrame((k, x) for k,v in merge_same_langs.items() for x in v)
df=df.rename(columns = {0:'BugID', 1: 'Language'})
df.loc[(df['Language']=='cpp'), 'Language']='C++'
df.loc[(df['Language']=='js'), 'Language']='JS'
df.loc[(df['Language']=='html'), 'Language']='HTML'
df.loc[(df['Language']=='c'), 'Language']='C'
df.loc[(df['Language']=='py'), 'Language']='Python'
df.loc[(df['Language']=='xml'), 'Language']='XML'
df.loc[(df['Language']=='java'), 'Language']='JAVA'
df.loc[(df['Language']=='CSS'), 'Language']='CSS'


df_final = (df.groupby(['BugID']).agg({'Language': lambda x: x.tolist()}).reset_index())

# df_final.to_csv('../data/Firefox/Languages_Firefox.csv', index= False)