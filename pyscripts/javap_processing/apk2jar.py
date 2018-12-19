import sys, os
def process(apk_list_file,apk_dir,jar_dir, script_file, convert_program='/media/duy/DSSD4/ResearchSpace/sandbox_two/programs/dex2jar-2.0/d2j-dex2jar.sh'):
    with open(apk_list_file) as reader:

        lines =[l.strip().split() for l in reader]
        interested_apks=set([e[0] for e in lines]+[e[1] for e in lines])
    apk_dir = os.path.abspath(apk_dir)
    cmds=[]
    if not os.path.isdir(jar_dir):
        os.makedirs(jar_dir)
    for id in interested_apks:
        apk_file = apk_dir+'/'+id+'.apk'
        if not os.path.isfile(apk_file):
            print("ERROR: cannot find",apk_file)
            #sys.exit(0)
        apk_file = apk_file
        jar_file = jar_dir+'/'+id+'.jar'

        cmd = 'bash '+convert_program+' '+apk_file+' -o '+jar_file
        cmds+=[cmd]
    if not os.path.isdir(jar_dir):
        os.makedirs(jar_dir)
    jar_dir = os.path.abspath(jar_dir)
    with open(script_file,'w') as writer:
        writer.write('\n'.join(cmds))
if __name__=='__main__':
    process('/media/duy/DSSD4/ResearchSpace/sandbox_two/SANER_apps/10small_apps.txt'
    ,'/media/duy/DSSD4/ResearchSpace/sandbox_two/SANER_apps/apks'
    ,'/media/duy/DSSD4/ResearchSpace/sandbox_two/SANER_apps/jars'
    ,'/media/duy/DSSD4/ResearchSpace/sandbox_two/SANER_apps/bashscripts/apk2jar.sh')
    
