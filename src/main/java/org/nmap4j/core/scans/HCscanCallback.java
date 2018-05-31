package org.nmap4j.core.scans;

import org.nmap4j.core.nmap.ExecutionResults;

/**
 *
 * @author yusj
 * @date 2018/3/26
 */
public class HCscanCallback implements  IScanCallback{

    @Override
    public    void executionCompleted(ExecutionResults results) {
        String taskId=results.getTaskId();
        String output=results.getOutput();

        //回调处理
        System.out.println("callback:"+results.getTaskId());
        System.out.println("callback:"+output);
        System.out.println("callback:"+results.getErrors());
    }
}
