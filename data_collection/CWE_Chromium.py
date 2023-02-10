from HEADER import *


data=pd.read_csv('../data/Chromium/ISSUES.csv',low_memory=False)
CVE_List=list(set(data['CVE'].tolist()))

CVSS = []
Confidentiality = []
Integrity = []
Availability = []
Access = []
Authentication = []
Gained_Access = []
Vulnerability = []
CWE_ID = []
# main_url = "https://www.cvedetails.com/cve/CVE-2011-1185"
for id in CVE_List:
    time.sleep( 1.0 +  np.random.uniform(0,1))
    main_url = f'https://www.cvedetails.com/cve/{id}'
#     print(main_url)
    result = requests.get(main_url)
    soup = BeautifulSoup(result.text, 'html.parser')

    TABLE = soup.find("table", id = "cvssscorestable")

    if str(type(TABLE)) != "<class 'NoneType'>":
        for item in TABLE.select('tr'):
            # print(item.text)
            if 'CVSS Score' in item.text :
                for item2 in item.select('td .cvssbox'):
                    # print(f"CVSS Score = {item2.text}")
                    CVSS.append(item2.text)
            if 'Confidentiality Impact' in item.text :
                vt = ''
                for item2 in item.select('td span'):
                    vt = vt + item2.text + ' '
                print(f"Confidentiality Impact = {vt}")
                Confidentiality.append(vt)

            if 'Integrity Impact' in item.text :
                vt = ''
                for item2 in item.select('td span'):
                    vt = vt + item2.text + ' '
                    # print(f"Integrity Impact = {str(item2.text)}")
                Integrity.append(vt)

            if 'Availability Impact' in item.text :
                vt = ''
                for item2 in item.select('td span'):
                    vt = vt + item2.text + ' '
                    # print(f"Availability Impact = {str(item2.text)}")
                Availability.append(vt)

            if 'Access Complexity' in item.text:
                vt = ''
                for item2 in item.select('td span'):
                    vt = vt + item2.text + ' '
                    # print(f"Access Complexity = {str(item2.text)}")
                Access.append(vt)
            if 'Authentication' in item.text:
                vt = ''
                for item2 in item.select('td span'):
                    vt = vt + item2.text + ' '
                    # print(f"Authentication = {str(item2.text)}")
                Authentication.append(vt)
            if 'Gained Access' in item.text:
                vt = ''
                for item2 in item.select('td span'):
                    vt = vt + item2.text + ' '
                    # print(f"Gained Access = {str(item2.text)}")
                Gained_Access.append(vt)

            if 'Vulnerability Type(s)' in item.text:
                vt = ' '
                for item2 in item.select('td'):
                    if len(item2.text)<=1:
                        # print(f"Vulnerability Type(s) = N/A")
                        Vulnerability.append('')
                        break
                    else:
                        vt = vt + item2.text
                    # print(f"Vulnerability Type(s) = {item2.text}")
                    Vulnerability.append(item2.text)
            if 'CWE ID' in item.text:
                for item2 in item.select('td'):
                    # print(f"CWE ID = {item2.text}")
                    CWE_ID.append(item2.text)

                # print()
            # print(type(item))

    else:
        CVSS.append('Webpage N/A')
        Confidentiality.append('Webpage N/A')
        Integrity.append('Webpage N/A')
        Availability.append('Webpage N/A')
        Access.append('Webpage N/A')
        Authentication.append('Webpage N/A')
        Gained_Access.append('Webpage N/A')
        Vulnerability.append('Webpage N/A')
        CWE_ID.append('Webpage N/A')
df = pd.DataFrame({'CVE_ID':CVE_List,
                   'CVSS Score':CVSS,
                   'Confidentiality Impact':Confidentiality,
                   'Integrity Impact':Integrity,
                   'Availability Impact':Availability,
                   'Access Complexity':Access,
                   'Authentication':Authentication,
                   'Gained Access':Gained_Access,
                   'Vulnerability Type(s)':Vulnerability,
                   'CWE ID':CWE_ID})
CVE_Details=pd.read_csv('../data/Chromium/CVE_Details_Chromium.csv')

#######
CWE_ID=CVE_Details['CWE ID'].tolist()
CWE_ID=[x for x in CWE_ID if x !='CWE id is not defined for this vulnerability' and x != 'Webpage N/A']

Data = []
Nature = []
Name = []
Type = []
CWE = []
Not_Found = []

for id in tqdm(CWE_ID):
    print(id)
    # id = 522
    main_url = f'https://cwe.mitre.org/data/definitions/{id}'
    print(main_url)
    result = requests.get(main_url)
    soup = BeautifulSoup(result.text, 'html.parser')

    # print(soup)

    TABLE = soup.find("div", id="Membership")

    # print(TABLE.prettify())

    # exit(0)
    # print('\n\n\n')

    if str(type(TABLE)) != "<class 'NoneType'>":
        vt = ''

        for item2 in TABLE.select('div .tabledetail tbody tr'):
            T1 = item2.text
            for item3 in item2.select('span'):
                T2 = item3.text
            Type.append(T2)
            T1 = T1.replace(T2,' ')

            for item3 in item2.select('a'):
                T3 = item3.text
                Name.append(item3.text)

            T1 = T1.replace(T3, '')
            Data.append(T1)
            CWE.append(id)


    else:
        TABLE = soup.find("div", id="relevant_table")
        if str(type(TABLE)) != "<class 'NoneType'>":
            vt = ''
            for item in TABLE.select('tbody tr'):
                T1 = item.text
                print(f'T1 = {T1}')
                print('\n\n')

                for item2 in item.select('td span .tip'):
                    T2 = item2.text

                    print(f'Span T2 = {T2}')

                    T1 = T1.replace(T2,' ')
                Type.append(T2)
                print('\nName: ')
                for item2 in item.select('td a'):
                    print(f'Name : \t{item2.text}')
                    T3 = item2.text
                    Name.append(T3)

                    T1 = T1.replace(T3,'')

                print(f'T1 = {T1}')

                Data.append(T1)
                CWE.append(id)

        else:
            print(f"Not Found for {id}")
            Not_Found.append(id)


# Data = ['ChildOf 74', 'ParentOf 113', 'CanPrecede 117', 'ChildOf 664', 'ParentOf 770', 'ParentOf 771', 'ParentOf 779', 'ParentOf 920', 'ParentOf 1235', 'CanFollow 410', 'ChildOf 285', 'ParentOf 425', 'ParentOf 638', 'ParentOf 939', 'MemberOf 1000', 'ParentOf 269', 'ParentOf 282', 'ParentOf 285', 'ParentOf 286', 'ParentOf 287', 'ParentOf 346', 'ParentOf 923', 'ParentOf 942', 'ParentOf 1191', 'ParentOf 1220', 'ParentOf 1224', 'ParentOf 1231', 'ParentOf 1242', 'ParentOf 1252', 'MemberOf 635', 'MemberOf 699', 'HasMember 128', 'HasMember 190', 'HasMember 191', 'HasMember 192', 'HasMember 193', 'HasMember 197', 'HasMember 198', 'HasMember 369', 'HasMember 681', 'HasMember 839', 'HasMember 1077', 'ChildOf 825', 'PeerOf 415', 'CanFollow 364', 'CanPrecede 120', 'CanPrecede 123', 'ChildOf 284', 'ChildOf 345', 'PeerOf 451', 'ChildOf 345', 'ChildOf 668', 'ChildOf 285', 'ParentOf 276', 'ParentOf 277', 'ParentOf 278', 'ParentOf 279', 'ParentOf 281', 'ParentOf 1004', 'MemberOf 699', 'MemberOf 723', 'MemberOf 731', 'HasMember 276', 'HasMember 277', 'HasMember 278', 'HasMember 279', 'HasMember 280', 'HasMember 281', 'HasMember 618', 'HasMember 766', 'HasMember 767', 'ChildOf 732', 'ChildOf 119', 'ParentOf 121', 'ParentOf 122', 'ParentOf 123', 'ParentOf 124', 'CanFollow 822', 'CanFollow 823', 'CanFollow 824', 'CanFollow 825', 'MemberOf 700', 'HasMember 391', 'HasMember 395', 'HasMember 396', 'HasMember 397', 'ChildOf 666', 'ChildOf 675', 'ChildOf 825', 'PeerOf 123', 'PeerOf 416', 'CanFollow 364', 'ChildOf 693', 'ParentOf 329', 'ParentOf 331', 'ParentOf 334', 'ParentOf 335', 'ParentOf 338', 'ParentOf 340', 'ParentOf 344', 'ParentOf 804', 'ParentOf 1241', 'ChildOf 74', 'ParentOf 78', 'ParentOf 88', 'ParentOf 624', 'ParentOf 917', 'ChildOf 285', 'ParentOf 551', 'ParentOf 639', 'ParentOf 647', 'ParentOf 804', 'ChildOf 119', 'ParentOf 785', 'CanFollow 170', 'CanFollow 231', 'CanFollow 416', 'CanFollow 456', 'CanPrecede 123', 'ChildOf 754', 'ChildOf 710', 'ParentOf 690', 'CanFollow 252', 'CanFollow 789', 'ChildOf 74', 'ParentOf 80', 'ParentOf 81', 'ParentOf 83', 'ParentOf 84', 'ParentOf 85', 'ParentOf 86', 'ParentOf 87', 'ParentOf 692', 'PeerOf 352', 'PeerOf 494', 'CanFollow 113', 'CanFollow 184', 'CanPrecede 494', 'ChildOf 664', 'ParentOf 454', 'ParentOf 455', 'ParentOf 770', 'ParentOf 908', 'ParentOf 909', 'ParentOf 1051', 'ParentOf 1052', 'ParentOf 1188', 'ParentOf 1221', 'ChildOf 668', 'ChildOf 706', 'ParentOf 23', 'ParentOf 36', 'CanFollow 20', 'CanFollow 73', 'CanFollow 172', 'ChildOf 913', 'PeerOf 915', 'ChildOf 668', 'ChildOf 287', 'ParentOf 256', 'ParentOf 257', 'ParentOf 260', 'ParentOf 523', 'ParentOf 549', 'ParentOf 555', 'ChildOf 693', 'ParentOf 312', 'ParentOf 319', 'ParentOf 614', 'PeerOf 327', 'MemberOf 635', 'ChildOf 707', 'ParentOf 114', 'ParentOf 129', 'ParentOf 606', 'ParentOf 622', 'ParentOf 626', 'ParentOf 781', 'ParentOf 1173', 'CanPrecede 22', 'CanPrecede 41', 'CanPrecede 74', 'CanPrecede 119', 'MemberOf 700', 'HasMember 364', 'HasMember 367', 'HasMember 377', 'HasMember 382', 'HasMember 383', 'HasMember 384', 'HasMember 412', 'ChildOf 20', 'CanPrecede 119', 'CanPrecede 789', 'CanPrecede 823', 'ChildOf 664', 'ParentOf 8', 'ParentOf 22', 'ParentOf 134', 'ParentOf 200', 'ParentOf 374', 'ParentOf 375', 'ParentOf 377', 'ParentOf 402', 'ParentOf 427', 'ParentOf 428', 'ParentOf 491', 'ParentOf 492', 'ParentOf 493', 'ParentOf 522', 'ParentOf 524', 'ParentOf 552', 'ParentOf 582', 'ParentOf 583', 'ParentOf 608', 'ParentOf 642', 'ParentOf 732', 'ParentOf 767', 'ParentOf 927', 'ParentOf 1189', 'CanFollow 441', 'CanFollow 942', 'MemberOf 635', 'MemberOf 699', 'HasMember 73', 'HasMember 403', 'HasMember 410', 'HasMember 470', 'HasMember 502', 'HasMember 619', 'HasMember 641', 'HasMember 694', 'HasMember 763', 'HasMember 770', 'HasMember 771', 'HasMember 772', 'HasMember 826', 'HasMember 908', 'HasMember 909', 'HasMember 910', 'HasMember 911', 'HasMember 914', 'HasMember 915', 'HasMember 920', 'HasMember 1188', 'ChildOf 284', 'ParentOf 261', 'ParentOf 262', 'ParentOf 263', 'ParentOf 288', 'ParentOf 289', 'ParentOf 290', 'ParentOf 294', 'ParentOf 295', 'ParentOf 301', 'ParentOf 302', 'ParentOf 303', 'ParentOf 304', 'ParentOf 305', 'ParentOf 306', 'ParentOf 307', 'ParentOf 308', 'ParentOf 309', 'ParentOf 521', 'ParentOf 522', 'ParentOf 593', 'ParentOf 603', 'ParentOf 620', 'ParentOf 640', 'ParentOf 645', 'ParentOf 798', 'ParentOf 804', 'ParentOf 836', 'CanFollow 613', 'ChildOf 119', 'ParentOf 126', 'ParentOf 127', 'CanFollow 822', 'CanFollow 823', 'CanFollow 824', 'CanFollow 825', 'ChildOf 664', 'ParentOf 22', 'ParentOf 41', 'ParentOf 59', 'ParentOf 66', 'ParentOf 98', 'ParentOf 178', 'ParentOf 386', 'ParentOf 827', 'PeerOf 99', 'ChildOf 451', 'ChildOf 441', 'MemberOf 700', 'HasMember 256', 'HasMember 258', 'HasMember 259', 'HasMember 260', 'HasMember 261', 'HasMember 272', 'HasMember 284', 'HasMember 285', 'HasMember 330', 'HasMember 359', 'HasMember 798', 'MemberOf 934', 'MemberOf 1029', 'HasMember 321', 'HasMember 322', 'HasMember 323', 'HasMember 324', 'ChildOf 664', 'ParentOf 588', 'ParentOf 681', 'ParentOf 843', 'ChildOf 682', 'ChildOf 287', 'ParentOf 296', 'ParentOf 297', 'ParentOf 298', 'ParentOf 299', 'ParentOf 599', 'PeerOf 322', 'MemberOf 635', 'MemberOf 699', 'HasMember 261', 'HasMember 324', 'HasMember 325', 'HasMember 328', 'HasMember 331', 'HasMember 334', 'HasMember 335', 'HasMember 338', 'HasMember 347', 'HasMember 916', 'HasMember 1240', 'ChildOf 682', 'ChildOf 668', 'ParentOf 201', 'ParentOf 203', 'ParentOf 209', 'ParentOf 213', 'ParentOf 215', 'ParentOf 359', 'ParentOf 497', 'ParentOf 538', 'ParentOf 1243', 'CanFollow 498', 'CanFollow 499', 'ChildOf 610', 'PeerOf 441', 'ChildOf 345', 'ChildOf 703', 'ParentOf 252', 'ParentOf 253', 'ParentOf 273', 'ParentOf 354', 'ParentOf 394', 'ParentOf 476', 'ChildOf 284', 'ParentOf 552', 'ParentOf 732', 'ParentOf 862', 'ParentOf 863', 'ParentOf 926', 'ParentOf 927', 'ParentOf 1230', 'ParentOf 1244', 'MemberOf 1000', 'ParentOf 128', 'ParentOf 131', 'ParentOf 135', 'ParentOf 190', 'ParentOf 191', 'ParentOf 193', 'ParentOf 369', 'ParentOf 467', 'ParentOf 468', 'ParentOf 469', 'CanFollow 681', 'CanFollow 839', 'CanPrecede 170', 'ChildOf 693', 'ParentOf 328', 'ParentOf 780', 'ParentOf 916', 'ParentOf 1240', 'PeerOf 311', 'PeerOf 301', 'CanFollow 208', 'ChildOf 284', 'ParentOf 250', 'ParentOf 266', 'ParentOf 267', 'ParentOf 268', 'ParentOf 270', 'ParentOf 271', 'ParentOf 274', 'ParentOf 648', 'ChildOf 691', 'ParentOf 364', 'ParentOf 366', 'ParentOf 367', 'ParentOf 368', 'ParentOf 421', 'ParentOf 1223', 'CanFollow 662', 'ChildOf 404', 'ParentOf 401', 'ParentOf 775', 'ParentOf 1091', 'CanFollow 911', 'ChildOf 691', 'ChildOf 913', 'ChildOf 74', 'ParentOf 95', 'ParentOf 96', 'CanFollow 98', 'ChildOf 610', 'ChildOf 362', 'ParentOf 363', 'ParentOf 365', 'PeerOf 386', 'CanFollow 609', 'MemberOf 699', 'HasMember 130', 'HasMember 166', 'HasMember 167', 'HasMember 168', 'HasMember 178', 'HasMember 182', 'HasMember 186', 'HasMember 229', 'HasMember 233', 'HasMember 237', 'HasMember 241', 'HasMember 409', 'HasMember 471', 'HasMember 472', 'HasMember 601', 'HasMember 611', 'HasMember 624', 'HasMember 625', 'HasMember 776', 'HasMember 1024', 'MemberOf 1000', 'ParentOf 118', 'ParentOf 221', 'ParentOf 372', 'ParentOf 400', 'ParentOf 404', 'ParentOf 405', 'ParentOf 410', 'ParentOf 471', 'ParentOf 487', 'ParentOf 488', 'ParentOf 495', 'ParentOf 496', 'ParentOf 498', 'ParentOf 499', 'ParentOf 501', 'ParentOf 580', 'ParentOf 610', 'ParentOf 662', 'ParentOf 665', 'ParentOf 666', 'ParentOf 668', 'ParentOf 669', 'ParentOf 673', 'ParentOf 704', 'ParentOf 706', 'ParentOf 749', 'ParentOf 911', 'ParentOf 913', 'ParentOf 922', 'ParentOf 1229', 'ParentOf 1246', 'ParentOf 1250', 'ChildOf 682', 'PeerOf 128', 'CanPrecede 119', 'ChildOf 834', 'ChildOf 118', 'ParentOf 120', 'ParentOf 125', 'ParentOf 466', 'ParentOf 680', 'ParentOf 786', 'ParentOf 787', 'ParentOf 788', 'ParentOf 805', 'ParentOf 822', 'ParentOf 823', 'ParentOf 824', 'ParentOf 825', 'CanFollow 20', 'CanFollow 128', 'CanFollow 129', 'CanFollow 131', 'CanFollow 190', 'CanFollow 193', 'CanFollow 195', 'CanFollow 839', 'CanFollow 843', 'ChildOf 77', 'CanAlsoBe 88', 'CanFollow 184']

MemberOf = []
HasMember = []
Nature = []
Id = []
for d in Data:
    print(d)
    tmp = d.split(' ')
    print(tmp)
    Nature.append(tmp[0])
    Id.append(tmp[1])
df_cwe = pd.DataFrame({"CWE ID":CWE,
                   "Nature":Nature,
                   "Id":Id,
                   "Type":Type,
                   "Name":Name})

# df_cwe.to_csv('../data/Chromium/CWE_Categories_Chromium.csv')

####Broadtype_Names

Data = []
Nature = []
Name = []
Type = []
CWE = []
Not_Found = []
NAME_of_Error = []

Frequence_List = []
for id in tqdm.tqdm(CWE_ID):
    print(id)
    # id = 522
    main_url = f'https://cwe.mitre.org/data/definitions/{id}'
    print(main_url)
    result = requests.get(main_url)
    soup = BeautifulSoup(result.text, 'html.parser')
    TABLE = soup.find("title")
    print(TABLE.text)
    mystring = TABLE.text
    Name = ' '.join(mystring.split())
    Name = Name.replace('CWE - ', '')
    Name = Name.replace(' (4.0)', '')
    Name = Name.replace(f"CWE-{id}: ", '')
    print(Name)
    CWE.append(id)
    NAME_of_Error.append(Name)

CWE_Names = pd.DataFrame({'CWE':CWE,
                   "Name":NAME_of_Error})
CWE_Names['CWE']=CWE_Names['CWE'].apply('int64')

# CWE_Names.to_csv('../data/Chromium/CWE_with_Name_Chromium.csv')

#Cleaning and merging with the main data
#First we clean the CVEs in the main data (i.e., duplicate reports of the original report have the same CVE IDs and etc)
#Then we add the collected broadtype names to the data using the CVE ids of the reports

data_chromium=pd.read_csv('../data/Chromium/ISSUES.csv',low_memory=False)

final_dict={}
ids=data_chromium[['LocalID','PseudoID']]
dict_ids = ids.groupby(by=['LocalID','PseudoID']).agg('count')
for LocalID, PseudoID in dict_ids.index:
    final_dict.setdefault(PseudoID,[]).append(LocalID)

data_chromium.loc[data_chromium['CVE'].isna(), 'CVE'] = 'NA'
data_chromium['CVE']=data_chromium['CVE'].apply(str)

#dictionary of reports and their corresponding CVEs
dict_cve = {}
for key,value in final_dict.items():
    for every_id in value:
        temp=(data_chromium[(data_chromium['LocalID']==every_id)].CVE.tolist())
        if 'CVE' not in str(temp[0]):
            temp = ['NA']
        dict_cve[every_id]=temp

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
            print('key is na')
        else:
            print('none')

    final_list = list(set([item for sublist in final_list for item in sublist]))
    if (len(final_list) > 1) & ('NA' in final_list):
        final_list = [x for x in final_list if x != 'NA']
        if len(list(set(final_list))) > 1:
            final_list = ['NA']
        print(final_list)
    final_cve_dict[key] = final_list

#Adding the clean CVEs to the data
for key,value in final_cve_dict.items():
        if len(value)>1:
            print(key)
        data_chromium.loc[data_chromium['PseudoID']==key,'CVE_final']=value

#Merging broadtypes with the data using the CVE ids of the reports
cve_details=CVE_Details[['CVE_ID','CWE ID']]
cve_details.rename(columns={'CVE_ID':'CVE_final', 'CWE ID':'CWE'}, inplace = True)
data_chromium=data_chromium.merge(cve_details,on = 'CVE_final', how = 'left')


CWE_Names['CWE']=CWE_Names['CWE'].astype('str')
data_chromium['CWE']=data_chromium['CWE'].astype('str')
data_chromium=data_chromium.merge(CWE_Names, on = 'CWE', how = 'left')
print(len([x for x in (data_chromium['CWE'].tolist())if 'CWE id is not defined for this vulnerability' in x or 'Webpage N/A' in x]))
data_chromium.loc[data_chromium['CWE']=='CWE id is not defined for this vulnerability', 'CWE']=-1
data_chromium.loc[data_chromium['CWE']=='Webpage N/A', 'CWE']=-1
data_chromium.loc[data_chromium['CWE']=='nan', 'CWE']=-1
data_chromium['CWE']=data_chromium['CWE'].apply('int64')

# data_chromium.to_csv('../data/Chromium/ISSUES.csv', index=False)




#This file is written by Afiya and Soodeh
