import sys, os
def process(jar_dir,src_dir,script_file,prog_path='/media/duy/DSSD4/ResearchSpace/sandbox_two/jd-cli-0.9.2-dist/jd-cli'):
    if not os.path.isdir(src_dir):
        os.makedirs(src_dir)
    src_dir = os.path.abspath(src_dir)
    jar_dir = os.path.abspath(jar_dir)
    cmds=[]
    for f in os.listdir(jar_dir):
        if f.endswith('.jar') and os.path.isfile(jar_dir + '/' + f):
            out = src_dir+'/'+f.replace('.jar','.zip')
            f = jar_dir+'/'+f
            cmd = 'bash '+ prog_path+' '+ f +' -g ALL -oz '+out
            cmds+=[cmd]
    with open(script_file,'w') as writer:
        writer.write('\n'.join(cmds))
if __name__ == '__main__':
    process('jars','srcs','jar2src.sh')
