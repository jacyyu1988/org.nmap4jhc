package org.nmap4j.core.scans;


import org.nmap4j.core.flags.Flag;
import org.nmap4j.core.nmap.ExecutionResults;
import org.nmap4j.core.nmap.NMapExecutionException;
import org.nmap4j.core.nmap.NMapInitializationException;
import org.nmap4j.data.NMapRun;
import org.nmap4j.parser.OnePassParser;

import java.util.Map;

/**
 * 检测核心类
 * @author yusj
 * @date 2018/3/26
 */
public class HCscan extends BaseScan{

    /**
     * 构造器
     * @param path
     */
    public HCscan(String path){
        super(path);
    }


    /**
     * 实时检测  返回NmapRun对象
     * @param taskId  String 任务号
     * @param check_type  String 检测类型DOMAIN/IP
     * @param hosts  String[] 域名/IP
     * @param ports  String[] 端口
     * @param isPing  String 是否优先ping  Y/N
     * @param outTime  Integer  超时时间
     * @param hostgroup  线程数
     * @return  NMapRun  对象
     */
    public NMapRun synScan(String taskId,Flag check_type,
                              String hosts[],String [] excludeHosts, String ports[],
                              boolean isPing,Integer outTime,Integer hostgroup){


        this.includeHosts(hosts);
        this.excludeHosts(excludeHosts);
        this.argProps.setTaskId(taskId);

        if(check_type.equals(Flag.CHECK_TYPE_IP)){
            this.addPorts(ports);
            this.addFlag(Flag.NEVER_DO_DNS);
            this.addFlag(Flag.TCP_SYN_SCAN);
        }

        if(check_type.equals(Flag.CHECK_TYPE_DOMAIN)){
            this.addFlag(Flag.PING_SCAN);
        }

        if(!isPing){
            this.addFlag(Flag.NO_PING);
        }
        this.argProps.replaceFlag(Flag.HOST_TIMEOUT,outTime+"");
        this.argProps.replaceFlag(Flag.PARALLEL_MIN_HOST_GROUP_SIZE,hostgroup+"");

        OnePassParser parser = new OnePassParser() ;
        NMapRun nmapRun = getResultForObject();

        return nmapRun ;
    }


    /**
     * 同步检测，输入是文件
     * @param taskId  String  任务号
     * @param check_type String 检测类型
     * @param inputFile  String 输入文件绝对路径
     * @param ports  String[] 端口
     * @param isPing  String 是否优先ping   Y/N
     * @param outTime  Integer  超时时间
     * @param hostgroup  Integer 线程数
     * @return
     */
    public NMapRun synScanByFile(String taskId,Flag check_type,String inputFile,String [] excludeHosts,
                                 String ports[],boolean isPing,Integer outTime,Integer hostgroup){

        this.argProps.replaceFlag(Flag.INPUT_FILENAME,inputFile);
        this.excludeHosts(excludeHosts);
        this.argProps.setTaskId(taskId);

        if(check_type.equals(Flag.CHECK_TYPE_IP)){
            this.addPorts(ports);
            this.addFlag(Flag.NEVER_DO_DNS);
            this.addFlag(Flag.TCP_SYN_SCAN);
        }

        if(check_type.equals(Flag.CHECK_TYPE_DOMAIN)){
            this.addFlag(Flag.PING_SCAN);
        }

        if(!isPing){
            this.addFlag(Flag.NO_PING);
        }
        this.argProps.replaceFlag(Flag.HOST_TIMEOUT,outTime+"");
        this.argProps.replaceFlag(Flag.PARALLEL_MIN_HOST_GROUP_SIZE,hostgroup+"");

        NMapRun nmapRun = getResultForObject();

        return nmapRun ;
    }


    /**
     * 异步检测
     * @param taskId  String  任务号
     * @param check_type  String 检测类型  DOMAIN/IP
     * @param inputFile  String 输入文件路径
     * @param ports  String[] 端口
     * @param isPing  Y/N
     * @param outTime Integer
     * @param hostgroup Integer
     * @param callback 回调方法
     */
    public void asynScanByFile(String taskId,Flag check_type,String inputFile,String excludeHosts[],
                               String ports[],boolean isPing,Integer outTime,
                               Integer hostgroup,IScanCallback callback){


        this.argProps.replaceFlag(Flag.INPUT_FILENAME,inputFile);
        this.excludeHosts(excludeHosts);
        this.argProps.setTaskId(taskId);


        if(check_type.equals(Flag.CHECK_TYPE_IP)){
            this.addPorts(ports);
            this.addFlag(Flag.NEVER_DO_DNS);
            this.addFlag(Flag.TCP_SYN_SCAN);
        }

        if(check_type.equals(Flag.CHECK_TYPE_DOMAIN)){
            this.addFlag(Flag.PING_SCAN);
        }

        if(!isPing){
            this.addFlag(Flag.NO_PING);
        }
        this.argProps.replaceFlag(Flag.HOST_TIMEOUT,outTime+"");
        this.argProps.replaceFlag(Flag.PARALLEL_MIN_HOST_GROUP_SIZE,hostgroup+"");

        try {
            executeAsynchronousScan( callback );
        } catch (ParameterValidationFailureException e) {
            e.printStackTrace();
        } catch (NMapExecutionException e) {
            e.printStackTrace();
        }
    }


    /**
     *
     * @param taskId
     * @param check_type
     * @param inputFile
     * @param outputFile
     * @param ports
     * @param isPing
     * @param outTime
     * @param hostgroup
     * @param callback
     * @param params  扩展字段，可以给结果传值  {excludes:String[]  忽略的host}
     */
    public void asynScanByFileOutFile(String taskId,Flag check_type,String inputFile,String outputFile,
                                      String ports[],boolean isPing,Integer outTime,Integer hostgroup,
                                      IScanCallback callback,Map<String,Object> params){

        this.argProps.replaceFlag(Flag.INPUT_FILENAME,inputFile);
        this.setOutputType(OutputType.XML,outputFile);
        this.argProps.setTaskId(taskId);
        this.argProps.setParams(params);

        //excludes ips
        String excludes[]=(String[])params.get("excludes");
        if(excludes!=null&&excludes.length>0){
            this.excludeHosts(excludes);
        }

        if(check_type.equals(Flag.CHECK_TYPE_IP)){
            this.addPorts(ports);
            this.addFlag(Flag.NEVER_DO_DNS);
            this.addFlag(Flag.TCP_SYN_SCAN);
        }

        if(check_type.equals(Flag.CHECK_TYPE_DOMAIN)){
            this.addFlag(Flag.PING_SCAN);
        }

        if(!isPing){
            this.addFlag(Flag.NO_PING);
        }
        this.argProps.replaceFlag(Flag.HOST_TIMEOUT,outTime+"");
        this.argProps.replaceFlag(Flag.PARALLEL_MIN_HOST_GROUP_SIZE,hostgroup+"");





        try {
            executeAsynchronousScan( callback );
        } catch (ParameterValidationFailureException e) {
            e.printStackTrace();
        } catch (NMapExecutionException e) {
            e.printStackTrace();
        }
    }


    /**
     *
     * @param taskId
     * @param check_type
     * @param hosts
     * @param ports
     * @param isPing
     * @param outTime
     * @param hostgroup
     * @param callback
     */
    public  void asynScan(String taskId,Flag check_type,String[] hosts,String excludeHosts[], String ports[],boolean isPing,Integer outTime,Integer hostgroup,IScanCallback callback){

        this.includeHosts(hosts);
        this.excludeHosts(excludeHosts);
        this.argProps.setTaskId(taskId);

        if(check_type.equals(Flag.CHECK_TYPE_IP)){
            this.addPorts(ports);
            this.addFlag(Flag.NEVER_DO_DNS);
            this.addFlag(Flag.TCP_SYN_SCAN);
        }

        if(check_type.equals(Flag.CHECK_TYPE_DOMAIN)){
            this.addFlag(Flag.PING_SCAN);
        }

        if(!isPing){
            this.addFlag(Flag.NO_PING);
        }
        this.argProps.replaceFlag(Flag.HOST_TIMEOUT,outTime+"");
        this.argProps.replaceFlag(Flag.PARALLEL_MIN_HOST_GROUP_SIZE,hostgroup+"");

        try {
            executeAsynchronousScan( callback );
        } catch (ParameterValidationFailureException e) {
            e.printStackTrace();
        } catch (NMapExecutionException e) {
            e.printStackTrace();
        }
    }


    private NMapRun getResultForObject(){
        OnePassParser parser = new OnePassParser() ;
        //System.out.println("-----execute command-----|"+this.getExecutedCommand());
        NMapRun nmapRun = null;
        try {
            ExecutionResults result=this.executeScan();
            System.out.println("-----execute command-----|"+this.getExecutedCommand());
            if(result.hasErrors()){
                throw new NMapExecutionException("CHECK ERROR:"+result.getErrors());
            }
            nmapRun=parser.parse(result.getOutput(),OnePassParser.STRING_INPUT);
            nmapRun.setTaskId(result.getTaskId());
        } catch (ParameterValidationFailureException e) {
            e.printStackTrace();
        } catch (NMapExecutionException e) {
            e.printStackTrace();
        } catch (NMapInitializationException e) {
            e.printStackTrace();
        }
        return nmapRun;
    }


}
