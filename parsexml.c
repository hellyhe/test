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

#include<stdio.h>
#include<string.h>
#include<libxml/parser.h>
#include<libxml/tree.h>
int parse_xml_file(char *buf,int len){
        xmlDocPtr doc;
        xmlNodePtr root,node,detail;
        xmlChar *name,*value;
        doc=xmlParseMemory(buf,len);    //parse xml in memory
        if(doc==NULL){
                printf("doc == null\n");
                return -1;
        }
        root=xmlDocGetRootElement(doc);
        for(node=root->children;node;node=node->next){
                if(xmlStrcasecmp(node->name,BAD_CAST"content")==0)
                        break;
        }
        if(node==NULL){
                printf("no node = content\n");
                return -1;
        }
        for(node=node->children;node;node=node->next){
                if(xmlStrcasecmp(node->name,BAD_CAST"pro")==0){         //get pro node
                        name=xmlGetProp(node,BAD_CAST"id");    
                        value=xmlNodeGetContent(node);
                        printf("this is %s:\n%s\n",(char*)name,(char*)value);   //get value, CDATA is not parse and don't take into value
                        xmlFree(name);
                        xmlFree(value);
                }else if(xmlStrcasecmp(node->name,BAD_CAST"details")==0){       //get details node
                        for(detail=node->children;detail;detail=detail->next){  //traverse detail node
                                if(xmlStrcasecmp(detail->name,BAD_CAST"detail")==0){
                                        name=xmlGetProp(detail,BAD_CAST"name");
                                        value=xmlNodeGetContent(detail);
                                        if(strlen((char*)value)!=0){
                                                printf("%s : %s\n",(char*)name,(char*)value);                                      
                                         }else{
                                                printf("%s has no value\n",(char*)name);
                                        }
                                        xmlFree(name);
                                        xmlFree(value);
                                }
                        }
                }
        }
        xmlFreeDoc(doc);
        return 0;
}
int main(void){
        char *content;
        unsigned long filesize;
        FILE *file;
        if((file=fopen("testxml","r"))==NULL){
                perror("openf file error");
        }
        fseek(file,0,SEEK_END);
        filesize=ftell(file);
        rewind(file);
        content=(char *)malloc(filesize+1);
        memset(content,0,filesize+1);
        fread(content,1,filesize,file);
        fclose(file);
        printf("content:\n%s\n",content);
        if(parse_xml_file(content,filesize)<0){
                perror("parse xml failed");
        }
        return 0;
}