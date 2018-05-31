package org.nmap4j.core.scans;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * 并行处理runtime返回结果
 * @author yusj
 * @date 2018/4/8
 */
public class RetThread extends Thread{
    private InputStream inputStream;
    private String outPut;


    public RetThread(InputStream  input){
        this.inputStream=input;
    }

    @Override
    public void run() {
        BufferedReader streamReader=null;
        try {
            String output;
            StringBuffer outputBuffer = new StringBuffer() ;
            streamReader = new BufferedReader(
                    new InputStreamReader( inputStream ) ) ;
            System.out.println(streamReader.readLine());
            while ( ( output = streamReader.readLine() ) != null ) {
                outputBuffer.append( output ) ;
                outputBuffer.append( "\n" ) ;
            }
            this.outPut=outputBuffer.toString();

        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            if(streamReader !=null){
                try {
                    streamReader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            if(inputStream !=null){
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public String getOutPut(){
        return this.outPut;
    }


}
