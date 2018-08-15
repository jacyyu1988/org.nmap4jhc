package org.nmap4j.core.scans;

import org.junit.Test;
import org.nmap4j.core.flags.Flag;
import org.nmap4j.data.NMapRun;

import java.util.HashMap;
import java.util.Map;

/**
 * 核心检测类测试
 * Created by yusj on 2018/3/26.
 */

public class HCScanTest {
    //@Test
    public void testIpPortScan(){
        HCscan scan=new HCscan("C:\\Program Files (x86)\\Nmap");
        String hosts[]=new String[]{"192.168.1-2.122-123","192.168.1.123","192.168.1.125","192.168.1.105"};
        String domains[]=new String[]{"www.dazheng-group.com","www.hljitpc.org.cn"};
        String ports[]=new String[]{"3306","8080-8089"};
        String filePath="";

        //同步
        //NMapRun runR=scan.synScan("001", Flag.CHECK_TYPE_DOMAIN,domains,ports,true,2000,10);
        //System.out.println(runR.toString());



        //异步
        HCscanCallback  callback=new HCscanCallback();
        //scan.asynScan("001",Flag.CHECK_TYPE_IP,hosts,ports,true,2000,20,callback);

        System.out.println(scan.getExecutedCommand());

    }


    public static void main(String args[]){
        HCscan scan=new HCscan("C:/Program Files (x86)/Nmap");
        HCscan scan1=new HCscan("C:\\Program Files (x86)\\Nmap");
        HCscan scan2=new HCscan("C:\\Program Files (x86)\\Nmap");

        String hosts[]=new String[]{"192.168.1-2.122-123","192.168.1.123","192.168.1.125","192.168.1.105"};
        String ports[]="19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,3306,1521,8080-8090".split(",");
        String exludes[]=new String[]{"192.168.1.1"};
        String domains[]=new String[]{"www.dazheng-group.com","www.hljitpc.org.cn"};
        String filePath="";


        String hosts1[]=new String[]{"192.168.1-2.122-123","192.168.1.123","192.168.1.125","192.168.1.105"};
        String ports1[]=new String[]{"3306","8080-8089"};
        String exludes1[]=new String[]{"192.168.1.122"};
        String hosts2[]=new String[]{"192.168.1-2.122-123","192.168.1.123","192.168.1.125","192.168.1.105"};
        String ports2[]=new String[]{"3306","8080-8089"};



        //同步
        /*NMapRun runR=scan.synScan("001", Flag.CHECK_TYPE_DOMAIN,domains,ports,true,2000,10);
        System.out.println(runR.toString());
        System.out.println(scan.getExecutedCommand());*/


        /*NMapRun runR1=scan.synScan("001", Flag.CHECK_TYPE_IP,hosts1,ports1,true,2000,10);
        System.out.println(runR1.toString());
        System.out.println(scan1.getExecutedCommand());*/


        //异步add achange
        HCscanCallback  callback=new HCscanCallback();
        HCscanCallback  callback1=new HCscanCallback();
        HCscanCallback  callback2=new HCscanCallback();

        System.out.println(scan.getPool().toString());

        Map<String,Object> params=new HashMap<String,Object>();
        params.put("test","22222");
        params.put("excludes",exludes);


        /*scan.asynScanByFileOutFile("1234",Flag.CHECK_TYPE_IP,
                "C:\\Users\\yusj\\Desktop\\ex.txt",
                "C:\\Users\\yusj\\Desktop\\test_out.xml",
                 ports,false,2000,
                10,callback,params);*/

        scan.asynScan("001",Flag.CHECK_TYPE_IP,hosts,exludes,ports,true,2000,20,callback);
        //scan.asynScanByFile("002",Flag.CHECK_TYPE_IP,"C:\\Users\\yusj\\Desktop\\ex.txt",exludes,ports,true,2000,20,callback);
        //scan.asynScanByFile("002",Flag.CHECK_TYPE_IP,"C:\\Users\\yusj\\Desktop\\ex1.txt",exludes1,ports1,true,2000,20,callback);
        //scan.asynScan("002",Flag.CHECK_TYPE_IP,hosts1,ports1,true,2000,20,callback1);
        //scan.asynScan("001",Flag.CHECK_TYPE_IP,hosts2,ports2,true,2000,20,callback2);

        System.out.println(scan.getPool().toString());
    }










}
