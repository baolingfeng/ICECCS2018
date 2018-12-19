import sys,os,tarfile
def read_permissions(f):
    with open(f,'r') as reader:
        lines =[l.strip() for l in reader]
    line_index=0
    current_permission = None
    current_method_count = None
    current_method_set = set()
    ans={}
    while line_index < len(lines):
        if lines[line_index].startswith('Permission:'):
            for m in current_method_set:
                ans[m]=current_permission
            
            if current_method_count is not None and len(current_method_set)!=current_method_count:
                print("ERROR: inconsistent number of API methods")
                sys.exit(0)
            
            current_method_set=set()
            current_permission = lines[line_index]
            line_index+=1
            current_method_count = int(lines[line_index].split()[0])
        else:            
            current_method_set.add(lines[line_index])
        #####
        line_index+=1
    #####
    for m in current_method_set:
        ans[m]=current_permission
    return ans

def convert(method,type_mapping={'Z':'boolean','B':'byte','C':'char','S':'short','I':'int','J':'long','F':'float','D':'double'}):
    first,second = method.split(':')
    if '.' in first:
        classname, methodname = first.split('.')
    else:
        classname=''
        methodname = first
    ####
    return_type = second[second.rfind(')')+1:]
    
    ####
    parameter_types=second[second.find('(')+1:second.find(')')]+return_type
    index = 0
    paras=[]
    stack=[]
    while index < len(parameter_types):
        if parameter_types[index]=='[':
            index+=1
            stack+=['[]']
            ###
            index+=1
        elif parameter_types[index]=='L':
            last_index=index
            while parameter_types[last_index]!=';':
                last_index+=1
            
            t=parameter_types[index+1:last_index]
            if len(stack)>0 and stack[-1]=='[]':
                t=t+'[]'
                stack.pop()
            stack+=[t]
            ###
            index=last_index+1
        else:
            t=parameter_types[index]
            if len(stack)>0 and stack[-1]=='[]':
                t=t+'[]'
                stack.pop()
            stack+=[t]
            ###
            index+=1
    classname = classname.replace('/','.')
    stack =[e.replace('/','.') for e in stack]
    return_type=stack[-1]
    stack=stack[:-1]
    return (classname,return_type,methodname,stack)

def parse_invoked_methods( apk_file ):
    tar =tarfile.open(apk_file,'r:bz2')
    #print("Parsing",apk_file)
    methods=set()
    for member in tar.getmembers():
        reader = tar.extractfile(member)
        print("Reading",member.name)
        lines=[x.decode('utf8').strip()for x in reader]
        methods |=set([l.strip().split()[-1] for  l in lines if 'Methodref' in l])
    
    return [convert(m) for  m in methods]

def process(permission_mapping_file,methodref_dir,apk_pairs_file):
    method2permission = read_permissions(permission_mapping_file)
    
    apk_permissions={}
    for apk_file in os.listdir(methodref_dir):
        
        if not os.path.isfile(methodref_dir+'/'+apk_file):
            continue
        apk_id = apk_file[:apk_file.find('.')]

        invoked_methods=parse_invoked_methods(methodref_dir+'/'+apk_file)
        
        apk_permissions[apk_id]=set()
        
        for classname,return_type,methodname,paras in invoked_methods:
            sign = '<'+classname+':'+' '+return_type+' '+methodname+'('+','.join(paras)+')'+'>'
            if sign not in method2permission:
                continue
            p = method2permission[sign]
            apk_permissions[apk_id].add(p)
        print('APK:',apk_id)
        for p in apk_permissions[apk_id]:
            print("PERMISSION:",p)
        print()
    #####
    with open(apk_pairs_file,'r') as reader:
        pairs=[tuple(e.strip().split(',')) for e in reader]
    found_cases=set()
    for (benign,malicious) in pairs:
        benign_permissions = apk_permissions[benign]
        malicious_permissions = apk_permissions[malicious]
        if len(malicious_permissions-benign_permissions)>0:
            found_cases.add((benign,malicious))
    print("########################")
    for p in found_cases:
        print("PAIR",p[0],p[1])
    print("#FOUND CASES:",len(found_cases))


if __name__ == '__main__':
    permission_mapping_file='api_permission_mapping/jellybean_publishedapimapping.txt'
    methodref_dir='javap'
    apk_pairs_file='selected_apps.txt'
    process(permission_mapping_file,methodref_dir,apk_pairs_file)