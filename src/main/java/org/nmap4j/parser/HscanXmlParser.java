package org.nmap4j.parser;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;

import java.io.File;
import java.util.List;
import java.util.Set;

/**
 *
 * 解析xml ，将xml解析成cvs格式文件
 * @author yusj
 * @date 2018/5/7
 */
public class HscanXmlParser {

    /**
     * 解析xml
     * @param filePath
     * @param set
     */
    public static void parseNmapIpXml(String filePath,Set<String> set,
                                      long oversize,long synsize) throws Exception {
        File  file=new File(filePath);
        long size=file.length();


        if(size>oversize){
            throw new Exception("size:"+size+"too big");
        }


        if(size<synsize){
            parseNmapIpxmlSmall(filePath,set);
        }else{
            parseNmapIpxmlBig(filePath,set);
        }

    }


    private static void parseNmapIpxmlSmall(String filePath,Set<String> set) throws DocumentException {

        SAXReader reader = new SAXReader();
        Document document = reader.read(filePath);
        List<Node> listAddr=document.selectNodes("//host/address[@addr]");



        List<Node> listPort=document.selectNodes("//port[@portid]");

    }

    private static void parseNmapIpxmlBig(String filePath,Set<String> set){

    }


}
