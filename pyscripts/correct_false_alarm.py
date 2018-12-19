import sys,os,random,json,statistics
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn import svm
from sklearn.decomposition import TruncatedSVD
from sklearn.decomposition import PCA
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import Normalizer
import numpy as np
from sklearn.model_selection import LeaveOneOut

from sklearn.model_selection import PredefinedSplit
from sklearn.model_selection import GridSearchCV
def create_folds(apks,n_folds):
    apks=list(apks)
    apks.sort()
    random.shuffle(apks)
    ans=[]
    size=n_folds
    while size>0:
        n = (len(apks)+1)//size
        n = min(n,len(apks))
        ans+=[apks[:n]]
        apks=apks[n:]
        size-=1
    return ans
def parse_permissions(input_folder):
    ans={}
    for f in os.listdir(input_folder):
        if os.path.isfile(input_folder+'/'+f):
            id = f[:f.find('.')]
            f = input_folder+'/'+f
            ################
            apk=set()
            with open(f,'r') as reader:
                lines=[l.strip() for l in reader]
                for l in lines:
                    index = l.rfind('>')
                    method = l[:index+1].strip()
                    pstr =  l[index+1:].strip().split()
                    if len(pstr)>0:
                        apk|=set(pstr)
                    else:
                        continue
            #################
            ans[id]=apk
    return ans
def special_heading():
    return ['shared_preferences']
    #return ['hooked_method', 'shared_preferences', 'urls', 'broadcast_receivers', 'permissions', 'content_resolvers']
####################### USELESS CODE #######################

def string_edit_dist_diff(a,b):
    la = len(a)
    lb  = len(b)
    dp = [[None]*(lb+1)for _ in range(la+1)]
    for i in range(1,la+1):
        dp[i][0]=i
    for j in range(1,lb+1):
        dp[0][j]=j
    dp[0][0]=0
    for i in range(1,la+1):
        for j in range(1,lb+1):
            ca = a[i-1]
            cb = b[j-1]
            if ca==cb:
                dp[i][j]=dp[i-1][j-1]
            else:
                dp[i][j]=1+min([dp[i-1][j],dp[i][j-1],dp[i-1][j-1]])
    return dp[la][lb]
def string_jaccard_diff(a,b):
    a =set(list(a))
    b =set(list(b))
    return len(a&b)/len(a|b)
def is_outliner(instance, group,diff_method='edit_diff',debug=False):
    if len(group)==0 and len(instance)>0:
        return True
    group = list(group)
    diffs=[]
    instance_diffs=[]
    for i in range(len(group)):
        for j in range(i):
            if diff_method =='jaccard':
                diffs+=[ string_jaccard_diff(group[i],group[j]) ] 
            elif diff_method=='edit_diff':
                diffs+=[ string_edit_dist_diff(group[i],group[j]) ]
            else:
                print('unknown diff methods! ->',diff_method)
                sys.exit(0)
        #####################
        if diff_method =='jaccard':
            instance_diffs+=[ string_jaccard_diff(group[i],instance) ] 
        elif diff_method=='edit_diff':
            instance_diffs+=[ string_edit_dist_diff(group[i],instance) ]
    # if len(diffs)<2:
    #     print(diffs,instance_diffs,instance,group)
    group_mean,group_stddev  = statistics.mean(diffs) if len(diffs)>=1 else 0.0,statistics.stdev(diffs) if len(diffs)>=2 else 0.0
    #####################################################################
   
    similar=True
    for e in instance_diffs:
        if e> group_mean + group_stddev:
            similar=False
    similar = statistics.mean(instance_diffs) <= group_mean + group_stddev
    ###########################################################################
    if debug and not similar:
        print('========= DEBUG =========')
        print(group_mean,group_stddev)
        print(group_mean-group_stddev,group_mean+group_stddev)
        for e in instance_diffs:
            if e > group_mean + group_stddev:
                print("BAD DIFF:",e)
        print(instance,group)
    return True if not similar else False

##############################################################
def outliner_detection(test,train,dim=3,maxgram=10):
    if len(train)==0:
        return test
    test=list(set(test)-set(train))
    train = list(train)
    all=np.array(train+test)
    train_size=len(train)
    test_size= len(test)

    vectorizer = CountVectorizer(analyzer='char',ngram_range=(1,maxgram),lowercase=False)
    vectorizer.fit(all)
    all_tfidf=vectorizer.transform(all)

    svd = TruncatedSVD(n_components=dim, 
                         algorithm='randomized',
                         n_iter=10, random_state=8879)
    normalizer = Normalizer(copy=False)
    lsa = make_pipeline(svd, normalizer)
    X_all = lsa.fit_transform(all_tfidf)
    
    # pca = PCA(n_components=dim)
    # X_all = pca.fit_transform(all_tfidf)

    y_all = [1]*train_size +[-1]*test_size
    X_train = X_all[:train_size,:]
    X_test = X_all[train_size:,:]

    # X_train = all_tfidf[:train_size,:]
    # X_test = all_tfidf[train_size:,:]


    y_train =  [1]*np.shape(X_train)[0]
    ##########
    grid={'kernel':['sigmoid','poly','rbf','linear'],
    'nu':np.arange(0.01,1.01,0.01),#np.arange(0.05,1.02,0.05),
    'gamma':[0.01,0.05]+['auto'],
    'degree':np.arange(1,4,1)
    }
    tuner=GridSearchCV(svm.OneClassSVM(random_state=8879),param_grid=grid,cv=LeaveOneOut(),scoring='accuracy',n_jobs=16)
    tuner.fit(X_train,y_train)
    # print("BEST CONF:",tuner.best_estimator_)
    # print("BEST SCORE:",tuner.best_score_)
    clf = tuner.best_estimator_

    clf.fit(X_train,y_train)
    y_test=clf.predict(X_test)
    # print(y_test,test,train)
    return [test[i] for i in range(len(y_test)) if y_test[i]<0]
def compute_false_arlarms(apk_pairs,alldata_benign,headings,testcase_ids):
    TAR=0
    true_negatives=0
    false_positives=0
    detected_cases=[]
    undetected_cases=[]
    processed=set()
    for (benign,_) in apk_pairs:
        if benign in processed:
            continue
        processed.add(benign)
        for test_testcase in testcase_ids:
            raising_warning=False
            bad_values=None
            for head in headings:
                #train_data = alldata_benign[train_testcase][benign][head]
                train_data=set([e for train_index in testcase_ids for e in alldata_benign[train_index][benign][head] if train_index != test_testcase])
                test_data = alldata_benign[test_testcase][benign][head]
                unseen = [ e for e in test_data if e not in train_data]
                if len(unseen)>0:
                    if head in special_heading() and len(train_data)>0:
                        outliers=outliner_detection(unseen,train_data)
                    else:
                        print("Exception with",head)
                        outliers=unseen
                    if head not in special_heading() or len(outliers)>0:
                        raising_warning=True
                        bad_values=(head,outliers,train_data)
                        break
            ################
            if raising_warning:
                false_positives+=1
                detected_cases+=[(benign,)+bad_values]
            else:
                true_negatives+=1
                undetected_cases+=[benign]
    FAR  =100.0* false_positives/(false_positives+true_negatives)
    return FAR,true_negatives,false_positives,detected_cases,undetected_cases

def compute_false_arlarms2(apk_pairs,pair_data,headings,testcase_ids):
    TAR=0
    true_negatives=0
    false_positives=0
    detected_cases=[]
    undetected_cases=[]
    processed=set()
    for (benign,malicious) in apk_pairs:
        the_pair = (benign,malicious)
        for test_testcase in testcase_ids:
            raising_warning=False
            bad_values=None
            for head in headings:
                #train_data = alldata_benign[train_testcase][benign][head]
                train_data=set([e for train_index in testcase_ids for e in pair_data[train_index][the_pair]['benign'][head] if train_index != test_testcase])
                test_data = pair_data[test_testcase][the_pair]['benign'][head]
                unseen = [ e for e in test_data if e not in train_data]
                if len(unseen)>0:
                    # print('working on false alarm',head)
                    # print(train_data,unseen)
                    # print('------')
                    if head in special_heading() and len(train_data)>0:
                        try:
                            print('One-class SVM',head)
                            outliers=outliner_detection(unseen,train_data)
                        except Exception as e:
                            print("Exception with",head)
                            print(e)
                            outliers=unseen
                    else:
                        outliers=unseen
                    if head not in special_heading() or len(outliers)>0:
                        raising_warning=True
                        bad_values=(head,outliers,train_data)
                        break
            ################
            if raising_warning:
                false_positives+=1
                detected_cases+=[(benign,)+bad_values]
            else:
                true_negatives+=1
                undetected_cases+=[benign]
    FAR  =100.0* false_positives/(false_positives+true_negatives)
    return FAR,true_negatives,false_positives,detected_cases,undetected_cases


def revise_hooked_valuies(data,headname='hooked_method'):
    for test in data:
        for apk in data[test]:
            if headname in data[test][apk]:
                data[test][apk][headname] = set(filter(lambda x: x.startswith('android.'),data[test][apk][headname]))
            else:
                data[test][apk]['benign'][headname] = set(filter(lambda x: x.startswith('android.'),data[test][apk]['benign'][headname]))
                data[test][apk]['malicious'][headname] = set(filter(lambda x: x.startswith('android.'),data[test][apk]['malicious'][headname]))
    return data

def compute_true_arlarms(apk_pairs,pair_data,headings,testcase_ids):
    true_positives=0
    false_negatives=0
    cannot_detect=[]
    for (benign,malicious) in apk_pairs:
        the_pair = (benign,malicious)
        raise_warning=False
        for head in headings:
            train_data=set()
            test_data =set()
            for test_testcase in testcase_ids:
                train_data|=set(pair_data[test_testcase][the_pair]['benign'][head])
                test_data|=set(pair_data[test_testcase][the_pair]['malicious'][head])
            unseen = [ e for e in test_data if e not in train_data]
            # if the_pair in get_special_pairs() and head=='called_apis':
            #     print("FOUND->",unseen)
            #     print(test_data-train_data)
            #     print(test_data)
            #     print(train_data)
            # print('working on true alarm',head)

            if len(unseen)>0:
                if head in special_heading() and len(train_data)>0:
                    try:
                        print('One-class SVM TAR',head)
                        outliers=outliner_detection(unseen,train_data)
                    except Exception as e:
                        print("Exception TAR with",head)
                        outliers=unseen
                else:
                    outliers=unseen
                if head not in special_heading() or len(outliers)>0:
                    raise_warning=True
                    break
        if raise_warning:
            true_positives+=1
        else:
            false_negatives+=1
            cannot_detect+=[the_pair]
    TAR=100.0*true_positives/(true_positives+false_negatives)
    return TAR,true_positives,false_negatives,cannot_detect
def get_special_pairs():
    return [('3FCA7AC2ED1C542BAA476A4071DEA24E5AED3FA5C1D18D9CACF5337F3F10386C','B8510B58474093BDCC8DB1ECADFF7373CA9B024ABB2529FA308760A7AB3A1487')]
def process(apk_pairs_file,diff_folder,permission_list_folder,report_folder,n_folds=10, testcase_ids=['1','2','3']):
    headings=[]
    print(apk_pairs_file,diff_folder)
    interested_apks_list=set()
    with open(apk_pairs_file,'r') as reader:
        lines=[l.strip().replace(',','').split() for l in reader]
        lines=[list(filter(lambda x:len(x)>0,e))for e in lines]
        input_apk_pairs=set([(e[0],e[1]) for e in lines])
        interested_apks_list|=set([e[0] for e in lines])
        interested_apks_list|=set([e[1] for e in lines])
    print("FOUND benign apps",len(input_apk_pairs))
    ##############################################################
    alldata_benign={e:{} for e in testcase_ids}
    alldata_malicious={e:{} for e in testcase_ids}
    pair_data={e:{} for e in testcase_ids}
    headings=set(headings)
    for test_attempt in testcase_ids:
        for apk_name  in os.listdir(diff_folder+'/'+test_attempt):
            apk_file = diff_folder+'/'+test_attempt+'/'+apk_name
            ids = apk_name[:apk_name.rfind('.')]
            
            benign,malicious=ids.split('-')
            the_pair=benign,malicious
            if benign not in interested_apks_list or malicious not in interested_apks_list:
                continue
            with open(apk_file,'r') as f:
                data = json.load(f)
            alldata_benign[test_attempt][benign]=dict(data['origin_res'])
            alldata_malicious[test_attempt][malicious]=dict(data['repack_res'])
            
            pair_data[test_attempt][the_pair]={}
            pair_data[test_attempt][the_pair]['benign']=dict(data['origin_res'])
            pair_data[test_attempt][the_pair]['malicious']=dict(data['repack_res'])
            headings|=set(data['diff'])
    # p='3FCA7AC2ED1C542BAA476A4071DEA24E5AED3FA5C1D18D9CACF5337F3F10386C','B8510B58474093BDCC8DB1ECADFF7373CA9B024ABB2529FA308760A7AB3A1487'
    # a=pair_data['3'][p]['benign']['called_apis']
    # b=pair_data['3'][p]['malicious']['called_apis']
    # print(set(b)-set(a))
    # print()
    # print(b)
    # print(a)
    # print()
    # print(set(a)-set(b))
    # sys.exit(0)
    ##############################################################
    apks2permissions = parse_permissions(permission_list_folder)
    headings.add('permissions')
    for test in alldata_benign:
        for apk in alldata_benign[test]:
            alldata_benign[test][apk]['permissions']=apks2permissions[apk]
    
    for test in alldata_malicious:
        for apk in alldata_malicious[test]:
            alldata_malicious[test][apk]['permissions']=apks2permissions[apk]

    for test in pair_data:
        for the_pair in pair_data[test]:
            benign,malicious=the_pair
            pair_data[test][the_pair]['benign']['permissions']=apks2permissions[benign]
            pair_data[test][the_pair]['malicious']['permissions']=apks2permissions[malicious]

    ##############################################################
    benign_set=set([e[0] for e in input_apk_pairs])
    folds=create_folds(benign_set,n_folds)
    ###
    alldata_benign=revise_hooked_valuies(alldata_benign)
    alldata_malicious=revise_hooked_valuies(alldata_malicious)
    pair_data = revise_hooked_valuies(pair_data)
    #sys.exit(0)
    baseline_cases=set()
    for head in headings:
        continue
        #FAR,true_negatives,false_positives,malwares,no_malwares = compute_false_arlarms(input_apk_pairs,alldata_benign,[head],testcase_ids)
        TAR,true_positives,false_negatives, _ = compute_true_arlarms(input_apk_pairs,pair_data,[head],testcase_ids)
        FAR,true_negatives,false_positives,malwares,_ = compute_false_arlarms2(input_apk_pairs,pair_data,[head],testcase_ids)
        if head == 'called_sen_apis':
            baseline_cases = malwares
        print(head,'\t','%','FAR:',round(FAR,2),'%')
        print(head,'\t','TN:',true_negatives,'FP:',false_positives)
        print(head,'\t','%','TAR:',round(TAR,2),'%')
        print(head,'\t','TP:',true_positives,'FN:',false_negatives)
        print('==')
    print("-------")

    headings.remove('others')
    # headings.remove('urls')
    # headings.remove('content_resolvers')
    #headings.remove('hooked_method')
    
    #headings.remove('broadcast_receivers')
    #headings.remove('shared_preferences')

    #headings.remove('permissions')

    headings.remove('called_apis')
    headings.remove('called_sen_apis')
    
    print(headings)
    print('Exact String Matching')
    TAR,true_positives,false_negatives,cannot_detect = compute_true_arlarms(input_apk_pairs,pair_data,headings,testcase_ids)
    FAR,true_negatives,false_positives,detected_cases,undetected_cases = compute_false_arlarms2(input_apk_pairs,pair_data,headings,testcase_ids)
    print('ALL\t','\t','TN:',true_negatives,'FP:',false_positives)
    print('ALL\t','FAR:',FAR,'%')   
    print('ALL\t','\t','TP:',true_positives,'FN:',false_negatives)
    print('ALL\t','TAR:',TAR,'%')  

    ####
    if not os.path.isdir(report_folder):
        os.makedirs(report_folder)
    with open(report_folder+'/false_postive_values'+'.txt','w') as writer:
        processed=set()
        for benign,head,bad_value,train_data in detected_cases:
            if (benign,head)  in processed:
                continue
            processed.add((benign,head))
            writer.write('VERSION:'+benign+'\n')
            writer.write('HEADING:\t'+head+'\n')
            writer.write('BAD VALUES:\n')
            writer.write('\n'.join(bad_value)+'\n')
            writer.write('\n')
            writer.write('TRAIN VALUES:\n')
            writer.write('\n'.join(train_data)+'\n')
            writer.write('#######################################\n')
        writer.write('-------------------------------------------\n')
        writer.write('SENAPIS CASES:\n')
        writer.write('\n'.join([e[0] for e in baseline_cases]))
    with open(report_folder+'/false_negative_values'+'.txt','w') as writer:
        for (benign,malicious) in cannot_detect:
            writer.write(benign+'\t'+malicious+'\n')


if __name__=='__main__':
    apk_pairs_file='selected_apps.txt'
    diff_folder='sep_diff'
    permission_list_folder='to_record_methods'
    report_folder='reports/OUR_false_alarms'
    process(apk_pairs_file,diff_folder,permission_list_folder,report_folder)