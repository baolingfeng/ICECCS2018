import sys,os,json
import random
random.seed(2342423)

def compute_f1(true_negatives,true_positives,false_negatives,false_positives):
    precision  = true_positives/(true_positives+false_positives)
    recall = true_positives/(true_positives+false_negatives)
    f1 = 2.0 *precision*recall /(precision+recall) if precision+recall >0 else 0.0
    precision = round(100.0*precision,2)
    recall = round(100.0*recall,2)
    f1 = round(100.0*f1,2)
    return precision,recall,f1


def extract_data(apks_list,data):
    ans={}
    for apk in apks_list:
        for head in data[apk]:
            if head not in ans:
                ans[head]=set()
            ans[head]|=set(data[apk][head])
    return ans

def extract_gui_api_pair(data):
    ans=set()
    for gui in data:
        for api in data[gui]:
            ans.add((gui,api))
    return ans

def compute_false_alarms(apk_pairs,pair_data,testcase_ids):
    true_negatives=0
    false_positives=0
    for the_pair in apk_pairs:
        for testid in testcase_ids:
            test_data = pair_data[testid][the_pair]['benign']
            train_data =set()
            for e in testcase_ids:
                if e != testid:
                    train_data|=pair_data[e][the_pair]['benign']
            diff = test_data - train_data
            if len(diff)>0:
                false_positives+=1
            else:
                true_negatives+=1
    FAR = false_positives/(false_positives+true_negatives)
    return FAR,true_negatives,false_positives



def compute_true_alarms(apk_pairs,pair_data,testcase_ids):
    true_positives=0
    false_negatives=0
    for the_pair in apk_pairs:
        benign_data =set()
        malicious_data=set()
        for id in testcase_ids:
            benign_data|=pair_data[id][the_pair]['benign']
            malicious_data|=pair_data[id][the_pair]['malicious']
        diff = malicious_data-benign_data
        if len(diff)>0:
            true_positives+=1
        else:
            false_negatives+=1
    TAR  = true_positives/(true_positives+false_negatives)
    return TAR,true_positives,false_negatives


def process(apk_pair_file,data_folder,report_folder,testcase_ids=['1','2','3']):
    with open(apk_pair_file,'r') as reader:
        lines = [l.strip().replace(',',' ').split() for l in reader]
        apk_pairs = [ (e[0],e[-1]) for e in lines]
    ##############################################################
    headings=[]

    pair_data = {e:{} for e in testcase_ids}
    for test_attempt in testcase_ids:
        for apk_name  in os.listdir(data_folder+'/'+test_attempt):
            if not apk_name.endswith('.json'):
                continue
            
            apk_file = data_folder+'/'+test_attempt+'/'+apk_name
            
            # print('reading',apk_file)
            ids = apk_name[:apk_name.rfind('.')]
            if len(ids.split('-'))<2:
                print(ids)
            benign,malicious=ids.split('-')
            the_pair = benign,malicious
            if the_pair not in apk_pairs:
                continue
            with open(apk_file,'r') as f:
                data = json.load(f)
            pair_data[test_attempt][the_pair]={}
            pair_data[test_attempt][the_pair]['benign']=extract_gui_api_pair(data['origin'])
            pair_data[test_attempt][the_pair]['malicious']=extract_gui_api_pair(data['repack'])

    ##############################################################
    FAR,true_negatives,false_positives = compute_false_alarms(apk_pairs,pair_data,testcase_ids)
    TAR,true_positives,false_negatives = compute_true_alarms(apk_pairs,pair_data,testcase_ids)
    print('2nd baseline\t','TP:',true_positives,'FN:',false_negatives)
    print('2nd baseline\t','TAR:',TAR*100.0,'%')
    print()
    print('2nd baseline\t','TN:',true_negatives,'FP:',false_positives)
    print('2nd baseline\t','FAR:',FAR*100.0,'%')
if __name__=='__main__':
    apk_pair_file = 'selected_apps.txt'
    data_folder='sep_ui_diff'
    report_folder='reports/baseline_B'
    process(apk_pair_file,data_folder,report_folder)