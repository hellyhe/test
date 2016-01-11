/*<?xml version="1.0" encoding="utf-8"?>
<root name="test">
        <content>
                <pro id="moonApple"><![CDATA[<say>i still have lots to work on</say>]]></pro>
                <details>
                        <detail name="dancing">like it</detail>
                        <detail name="singing">poor , just listen</detail>
                        <detail name="laugh"/>
                        <detail name="eating"><![CDATA[<food>candy</food>]]></detail>
                </details>
        </content>
</root>
test.c文件：
*/

#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include "parsexml.h"


void getconfig(u_char *xmlfile)
{    
    xmlDocPtr doc;           //定义解析文档指针
    xmlNodePtr curNode;      //定义结点指针(你需要它为了在各个结点间移动) 
    xmlChar *szKey;          //临时字符串变量
    xmlChar *name,*value;

    doc = xmlReadFile(xmlfile,"GB2312",XML_PARSE_RECOVER); //解析文件
    //检查解析文档是否成功，如果不成功，libxml将指一个注册的错误并停止。
    //一个常见错误是不适当的编码。XML标准文档除了用UTF-8或UTF-16外还可用其它编码保存。
    //如果文档是这样，libxml将自动地为你转换到UTF-8。更多关于XML编码信息包含在XML标准中.

    if (NULL == doc) 
    {  
       fprintf(stderr,"Document not parsed successfully.\n");     
       return -1; 
    } 
    curNode = xmlDocGetRootElement(doc); //确定文档根元素
    /*检查确认当前文档中包含内容*/ 
    if (NULL == curNode)
    { 
       fprintf(stderr,"empty document\n");
       xmlFreeDoc(doc); 
       return -1; 
    } 

    /*在这个例子中，我们需要确认文档是正确的类型。“root”是在这个示例中使用文档的根类型。*/
    if (xmlStrcmp(curNode->name, BAD_CAST "config")) 
    {
       fprintf(stderr,"document of the wrong type, config node != config"); 
       xmlFreeDoc(doc); 
       return -1; 
    } else {
        name = xmlGetProp(curNode, BAD_CAST"threads");
        printf("%s->%s\n", "threads", (char*)name);
        //get value, CDATA is not parse and don't take into value
        xmlFree(name);
        
        name = xmlGetProp(curNode, BAD_CAST"nodes");
        printf("%s->%s\n", "nodes", (char*)name);  
        xmlFree(name);
        
        name = xmlGetProp(curNode, BAD_CAST"filter");
        printf("%s->%s\n","filter",(char*)name);  
        xmlFree(name);
        
        name = xmlGetProp(curNode, BAD_CAST"cpucore");
        printf("%s->%s\n","cpucore", (char*)name);
        xmlFree(name);
    }
    
    curNode = curNode->xmlChildrenNode;
    xmlNodePtr propNodePtr = curNode;
    while(curNode != NULL) 
    {      
        printf("%s -> %s\n","curNode.name", (char*)curNode->name); 
        if (!xmlStrcmp(curNode->name, BAD_CAST "dev")) 
        {
            name = xmlGetProp(curNode, BAD_CAST"send_name");
            printf("%s->%s\n", "send_name", (char*)name);   //get value, CDATA is not parse and don't take into value
            xmlFree(name);
            
            name = xmlGetProp(curNode, BAD_CAST"send_mac");
            printf("%s->%s\n", "send_mac", (char*)name);   //get value, CDATA is not parse and don't take into value
            xmlFree(name);
            
        } else if (!xmlStrcmp(curNode->name, BAD_CAST "task")) {
            
            name = xmlGetProp(curNode, BAD_CAST"host");
            printf("%s->%s\n", "host", (char*)name);   //get value, CDATA is not parse and don't take into value
            xmlFree(name);
            
            name = xmlGetProp(curNode, BAD_CAST"iptaskexpire");
            printf("%s->%s\n", "iptaskexpire", (char*)name);   //get value, CDATA is not parse and don't take into value
            xmlFree(name);
            
            xmlNodePtr subcurNode = curNode->xmlChildrenNode;
            while(subcurNode != NULL) 
            {
                if (!xmlStrcmp(subcurNode->name, BAD_CAST "white_uri")) 
                {
                    name = xmlGetProp(subcurNode, BAD_CAST"uri");
                    printf("%s->%s\n", "uri", (char*)name);   //get value, CDATA is not parse and don't take into value
                    xmlFree(name);
                    
                    name = xmlGetProp(subcurNode, BAD_CAST"percent");
                    printf("%s->%s\n", "percent", (char*)name);   //get value, CDATA is not parse and don't take into value
                    xmlFree(name);
                }
                if (!xmlStrcmp(subcurNode->name, BAD_CAST "src_addr")) 
                {   
                    name = xmlGetProp(subcurNode, BAD_CAST"url_regex");
                    printf("%s->%s\n", "url_regex", (char*)name);   //get value, CDATA is not parse and don't take into value
                    xmlFree(name);
                }
                if (!xmlStrcmp(subcurNode->name, BAD_CAST "dst_addr")) 
                {    
                    name = xmlGetProp(subcurNode, BAD_CAST"url");
                    printf("%s->%s\n", "url", (char*)name);   //get value, CDATA is not parse and don't take into value
                    xmlFree(name); 
                    
                    name = xmlGetProp(subcurNode, BAD_CAST"percent");
                    printf("%s->%s\n", "percent", (char*)name);   //get value, CDATA is not parse and don't take into value
                    xmlFree(name);
                    
                }
                subcurNode = subcurNode->next;  
                
            }
            
        }
        curNode = curNode->next;       
    } 
/*
    //查找属性
    xmlAttrPtr attrPtr = propNodePtr->properties;
    while (attrPtr != NULL)
    {
       if (!xmlStrcmp(attrPtr->name, BAD_CAST "attribute"))
       {
           xmlChar* szAttr = xmlGetProp(propNodePtr,BAD_CAST "attribute");
           printf("get attribute = %s\n", szAttr);
           xmlFree(szAttr);
       }
       attrPtr = attrPtr->next;
    }
    */
    xmlFreeDoc(doc);
    return 0;
}
