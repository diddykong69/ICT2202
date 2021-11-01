import inspect
import hashlib
import urllib
import urllib2
import json
import time
import ConfigParser
import re
import threading

from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from com.williballenthin.rejistry import RegistryHiveFile
from com.williballenthin.rejistry import RegistryKey
from com.williballenthin.rejistry import RegistryParseException
from com.williballenthin.rejistry import RegistryValue
from java.io import File
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import Arrays
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import Blackboard
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.modules.interestingitems import FilesSetsManager
from org.sleuthkit.datamodel import Score

configFileName="C:\test\VirusTotal.config"

def prettyPrintDict (d, file, depth=999, indent=0):
    if not file or not d:
        return
    for key,value in d.iteritems():
        file.write('\t' * indent + str(key) + '\n')
        if isinstance(value,dict):
                prettyPrintDict(value,file,depth,indent + 1)
        else:
                file.write('\t' * (indent+1)+str(value)+'\n')
    else:
        file.write('\t' * (indent+1)+str(value)+'\n')


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class VirusTotalFileIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "VirusTotalModule"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module checks file's md5 hash against VirusTotal Public API"

    def getModuleVersionNumber(self):
        return "1.0"

    def isFileIngestModuleFactory(self):
        return True
    
    def createFileIngestModule(self,ingestOptions):
        return VirusTotalFileIngestModule()

Class VirusTotalFileIngestModule(FileIngestModule):
    _logger=Logger,getLogger(VirusTotalFileIngestModuleFactory.moduleName)

    def log(self,level,msg):
        self._logger.logp(level,self.__class__.__name__,inspect.stack()[1][3],msg)

    def startUp(self,context):
        self.filesFound = 0
        self.apikey= "e2e6565a14c41edc76803c97da0d9000d4ab14a95991c34da94371e51ace787d"
        self.nbrOfFilesToProccessperThread = 5
        self.timetoPause = 20
        self.isprivateApi = 0

      try:
            config = ConfigParser.ConfigParser()
            config,read(configFileName)
            self.apiKey= config.get('VirusTotalApi','apiKey')
            
            except:
                self.log(Level.SEVERE,"Fail")
                self.nbrOfFilesToProccessperThread = 5
                self.timetoPause=20
                self.isprivateApi=0
        except ConfigParser.NoOptionError as inst:
            option,section = inst.args
            raise IngestModule.IngestModuleException("Corect")
        except:
            raise IngestModule.IngestModuleException("error")
        pass

    def process(self,file):
        if ((file.getType()==TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or 
                (file.getType()==TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or  
                (file.isFile()==False)):
            return IngestModule.ProcessResult.OK

    md5Hash=file.getMd5Hash()
    if not md5Hash:
        return IngestModule.ProcessResult.OK
    else:
        self.filesFound += 1
        if self.isPrivateApi:
                vtLabel=self.processVirusTotalApi(file)
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,VirusTotalFileIngestModuleFactory.moduleName, vtLabel)
                art.addAttribute(att)
        else:
            if self.filesFound < self.nbrOfFilesToProccessperThread:
                vtLabel = self.processVirusTotalApi(file)
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,VirusTotalFileIngestModuleFactory.moduleName, vtLabel)
                art.addAttribute(att)
                time.sleep(self.timetoPause)

    IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(VirusTotalFileIngestModuleFactory.moduleName,BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT,NONE));
    return IngestModule.ProcessResult.OK

def processVirusTotalApi(self,file):
    hash = file.getMd5Hash()
    hash=hash.strip()
    if not hash:
        return "VirusTotal Bad Hash"
    elif not re.findall(r"([a-fA-F\d]{32})",hash):
        return "VirusTotal Bad Hash"
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource":hash,
                    "apikey":self.apiKey}

    data = urllib.urlencode(parameters)
    req = urllib2.urlopen (req)
    if response.code ==200:
        try:
            response_dict = loads(response.read())
            vtCode = response_dict.get("response_code")
            if vtCode==1:
                matches=response_dict.get("positives")
                if matches > 0:
                    lock = threading.RLock()
                    with lock:
                        outfile = open("C:\foundhash.txt","a+")
                        outfile.write("\n\n\n")
                        outfile.write("Virus found for file: ")
                        outfile.write(file.getName())
                        outfile.write("\n")
                        prettyPrintDict(response_dict,outfile,1,0)
                        outfile.close()
                    return "VirusTotal Detected Virus"
                else:
                    if self.createOutputForKnown:
                            lock = threading.RLock()
                            with lock:
                                outfile = open ("C\FoundHash.txt","a+")
                                outfile.write("\n\n\n")
                                outfile.write("VT known file: ")
                                outfile.write(file.getName())
                                outfile.write("\n")
                                prettyPrintDict(response_dict,outfile,1,0)
                                outfile.close()
                    return "Virus total no match"
            elif vtCode == 0:
                return "Unknown to VirusTotal"
        except:
            return "VirusTotal bad data"
    else:  
        return "VirusTotal Quota Error"

def shutDown(self):
    message=IngestMessage.createMessage(IngestMessage.MessageType.Data,VirusTotalFileIngestModuleFactory.moduleName,str(self.filesFound)+"files found
    ")
    IngestServices = IngestServices.getInstance().postMessage(message)