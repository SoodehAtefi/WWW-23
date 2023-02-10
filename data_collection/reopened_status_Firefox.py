from HEADER import *

data=pd.read_csv('./data/data_not_clean.csv',na_filter=False)
ids=data['BugID'].tolist()
ids=[str(x) for x in ids]
urls=['https://bugzilla.mozilla.org/show_bug.cgi?id='+str(x) for x in ids]

reopened_issues = []
df_reopened = pd.DataFrame()
len_comments = []
for each_url in tqdm.tqdm(urls):
    #     time.sleep( 0.5 +  np.random.uniform(0,1))
    r = requests.get(each_url)
    page_data = r.text
    d_all_comments =  BeautifulSoup(page_data, 'lxml').findAll('div', class_='change-set')
    for x in d_all_comments:
        if x.find('div', class_='activity'):
            temp = x.find('div', class_='activity').findAll('div', class_='change')
            for i in range(len(temp)):
                if ' → REOPENED' in temp[i].text:
                    reopened_issues.append(each_url)
                    len_comments.append(len(d_all_comments))

reopened_issues = [reopened_issues[i].split('=')[1] for i in range(len(reopened_issues))]
reopened_issues = [int(x) for x in reopened_issues]
df_reopened['BugID'] = reopened_issues
df_reopened['NumberOfComments'] = len_comments


# df_reopened.to_csv('../data/Firefox/issues_reopened_Firefox.csv', index = False)