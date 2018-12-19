import json
import sys, os
import random
import statistics 
random.seed(8)
sys.path.append('pyscripts')
import correct_false_alarm as correct_false_alarm


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

def extract_data(apks,alldata,headings):
    ans={head:set() for head in headings}
    for head in headings:
        for apk in apks:
            ans[head]|=set(alldata[apk][head])
    return ans

def is_different(train_info,test_info,headings,edit_distance):
    for header in headings:
        test_data = test_info[header]
        train_data = train_info[header]
        unseen_values = set([e for e in test_data if e not in train_data])
        if len(unseen_values)>0:
            if header not in correct_false_alarm.special_heading() or len(correct_false_alarm.outliner_detection(test_data,train_data))>0:
                return True            
    return False
        

def sandboxing_simulation(train_apks,test_apks,alldata,headings,edit_distance):
    train_info = extract_data(train_apks,alldata,headings)
    false_arlarms=0
    for benign_apk in test_apks:
        test_info  = extract_data([benign_apk],alldata,headings)
        if is_different(train_info,test_info,headings,edit_distance):
            false_arlarms+=1
    return false_arlarms


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

def compute_true_arlarms(apk_pairs,alldata_benign,alldata_malicious,headings,edit_distance=True):
    TAR=0
    detected_cases=[]
    undetected_cases=[]
    for (benign,malicious) in apk_pairs:
        raising_warning=False
        for head in headings:
            begin_data = alldata_benign[benign][head]
            malicious_data = alldata_malicious[malicious][head]
            unseen=[e for e in malicious_data if e not in begin_data]
            if len(unseen)>0:
                if len(unseen)>0:
                    if head in correct_false_alarm.special_heading():
                        outliers=correct_false_alarm.outliner_detection(unseen,begin_data)
                    else:
                        outliers=unseen
                    if head not in correct_false_alarm.special_heading() or len(outliers)>0:
                        raising_warning=True
                        bad_values=(head,outliers,begin_data)
                        break
        ################
        if raising_warning:
            TAR+=1
            detected_cases+=[(benign,)+bad_values]
        else:
            undetected_cases+=[(benign,malicious)]
    true_positives=TAR
    false_negatives=len(apk_pairs)-TAR
    return 100.0*TAR/len(apk_pairs),true_positives,false_negatives,detected_cases,undetected_cases

            
def compute_f1(true_negatives,true_positives,false_negatives,false_positives):
    precision  = true_positives/(true_positives+false_positives)
    recall = true_positives/(true_positives+false_negatives)
    f1 = 2.0 *precision*recall /(precision+recall) if precision+recall >0 else 0.0
    precision = round(100.0*precision,2)
    recall = round(100.0*recall,2)
    f1 = round(100.0*f1,2)
    return precision,recall,f1

def revise_hooked_valuies(data,headname='hooked_method'):
    for apk,mp in data.items():
        mp[headname] = set(filter(lambda x: x.startswith('android.'),mp[headname]))
    return data
        

def process(apk_pairs_file,diff_folder,permission_list_folder,report_folder,testcase_ids=['1','2','3'],headings=['urls','shared_preferences','content_resolvers','broadcast_receivers','called_sen_apis']):
    
    print(apk_pairs_file,diff_folder)
    with open(apk_pairs_file,'r') as reader:
        lines=[l.strip().replace(',','').split() for l in reader]
        lines=[list(filter(lambda x:len(x)>0,e))for e in lines]
        input_apk_pairs=set([(e[0],e[1]) for e in lines])
    print("FOUND benign apps",len(input_apk_pairs))
    ##############################################################
    alldata_benign={}
    alldata_malicious={}
    headings=set(headings)

    print len(input_apk_pairs)

    for apk_name  in os.listdir(diff_folder):
        apk_file = diff_folder+'/'+apk_name
        ids = apk_name[:apk_name.rfind('.')]
        benign,malicious=ids.split('-')
        if (benign,malicious) not in input_apk_pairs:
            continue

        with open(apk_file,'r') as f:
            data = json.load(f)
        alldata_benign[benign]=data['origin_res']
        alldata_malicious[malicious]=data['repack_res']
        headings|=set(data['diff'])
    ##############################################################
    apks2permissions = parse_permissions(permission_list_folder)
    print len(alldata_benign.keys())
    headings.add('permissions')
    for apk in alldata_benign:
        alldata_benign[apk]['permissions']=apks2permissions[apk]
    for apk in alldata_malicious:
        alldata_malicious[apk]['permissions']=apks2permissions[apk]
    ##############################################################
    alldata_benign=revise_hooked_valuies(alldata_benign)
    alldata_malicious=revise_hooked_valuies(alldata_malicious)
    ##############################################################
    for head in headings:
        TAR,true_positives,false_negatives,_ ,_= compute_true_arlarms(input_apk_pairs,alldata_benign,alldata_malicious,[head])
        print(head,'\t','%','TAR:',round(TAR,2),'%')
        print(head,'\t','TP:',true_positives,'FN:',false_negatives)
        print('==')
    print("-------")


    headings.remove('others')
    headings.remove('called_apis')
    headings.remove('called_sen_apis')

    print(headings)
    # TAR,true_positives,false_negatives,detected_cases,undetected_ids = compute_true_arlarms(input_apk_pairs,alldata_benign,alldata_malicious,headings)
    # print('ALL\t','TP:',true_positives,'FN:',false_negatives)
    # print('ALL\t','TAR:',TAR,'%')
    print('Exact String Matching')
    TAR,true_positives,false_negatives,detected_cases,undetected_ids = compute_true_arlarms(input_apk_pairs,alldata_benign,alldata_malicious,headings,edit_distance=False)
    print('ALL\t','TP:',true_positives,'FN:',false_negatives)
    print('ALL\t','TAR:',TAR,'%')

    ########################################################

    if not os.path.isdir(report_folder):
        os.makedirs(report_folder)
    processed=set()
    with open(report_folder+'/detected'+'.txt','w') as writer:
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
    with open(report_folder+'/undetected.txt','w') as writer:
        for (benign,malicious) in undetected_ids:
            writer.write(benign+'---'+malicious+'\n')
if __name__=='__main__':
    apk_pairs_file='selected_apps.txt'
    diff_folder='sep_diff/1'
    permission_list_folder='to_record_methods'
    report_folder='reports/OUR_true_alarms'
    process(apk_pairs_file,diff_folder,permission_list_folder,report_folder)
    