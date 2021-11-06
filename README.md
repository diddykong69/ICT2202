# ICT2202

For our project, we have came up with a tool that parses locations on a windows machine where traces of malware will usually reside in, and outputs the results as findings under Autopsy. The tool is used to help digital forensics investator by streamlining certain parts of its process such as locating these files in their different locations. 

# Usage

Download the Autoruns.py file to a folder in your Autopsy's python module directory so that Autopsy is able to load the module. After selecting your data source, select run ingest module and choose the Autoruns module.
![image](https://user-images.githubusercontent.com/46297054/140603721-23590ec4-6dda-4b5a-ae3b-75d025a3152d.png)
![image](https://user-images.githubusercontent.com/46297054/140603733-c8d01f65-5bce-4377-b867-0bce2f52282f.png)

After the module finishes loading, the results will be stored as an Autopsy Blackboard artifact on the left hand side of the UI.

![image](https://user-images.githubusercontent.com/46297054/140603749-483f5f87-551e-4006-970a-e94556eb72d4.png)
