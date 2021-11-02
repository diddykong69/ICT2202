import inspect
import hashlib
import urllib
import urllib2
import json
import time
import ConfigParser
import re
import threading

# from simplejson import loads

from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
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

# TODO
configFileName = "D:\Autopsy\VirusTotal.config"

def prettyPrintDict(d, file, depth=999, indent=0):
    if not file or not d:
        return
        
    for key, value in d.iteritems():
        file.write('\t' * indent + str(key) + '\n')
        if isinstance(value, dict):
            if indent < depth:
                prettyPrintDict(value, file, depth, indent + 1)
            else:
                file.write('\t' * (indent + 1) + str(value) + '\n')
        else:
            file.write('\t' * (indent + 1) + str(value) + '\n')


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
        
    def createFileIngestModule(self, ingestOptions):
        return VirusTotalFileIngestModule()
        

class VirusTotalFileIngestModule(FileIngestModule):
    _logger = Logger.getLogger(VirusTotalFileIngestModuleFactory.moduleName)
    
    def log(self, level, msg):
        self._logger.logp(level, self._class_._name_, inspect.stack()[1][3], msg)
        
        
    def startUp(self, context):
        self.filesFound = 0
        # TODO
        self.apiKey = "d01451d7a0eedcdf4747cc180ca5318ff3f47e61e85cc55c2ef99febe05f2266"
        self.nbrOfFilesToProcessPerThread = 5
        self.timeToPause = 20
        self.isPrivateApi = 0
        
        try:
            config = ConfigParser.ConfigParser()
            config.read(configFileName)
            self.apiKey = config.get('VirusTotalApi', 'apiKey')
            
            try:
                self.nbrOfFilesToProcessPerThread = config.getint('VirusTotalApi', 'nbrOfFilesToProcessPerThread')
                self.timeToPause = config.getint('VirusTotalApi', 'timeToPause')
                self.isPrivateApi = config.getboolean('VirusTotalApi', 'isPrivateApi')
                self.createOutputForKnown = config.getboolean('VirusTotalApi', 'createOutputForKnown')
                
            except:
                self.log(Level.SEVERE, "Optional parameters processing failed; Setting all optional values to default")
                self.nbrOfFilesToProcessPerThread = 5
                self.timeToPause = 20
                self.isPrivateApi = 0
        except ConfigParser.NoOptionError as inst:
            option, section = inst.args
            raise IngestModule.IngestModuleException('Correct Virus Total configuration must be provided')
        except:
            raise IngestModule.IngestModuleException('Error loading config file')
        pass
    
    
    def process(self, file):
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or (file.isFile() == False)):
            return IngestModule.ProcessResult.OK
            
        md5Hash = file.getMd5Hash()
        if not md5Hash:
            return IngestModule.ProcessResult.OK
            
        else:
            self.filesFound += 1
            if self.isPrivateApi:
                vtLabel = self.processVirusTotalApi(file)
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, VirusTotalFileIngestModuleFactory.moduleName, vtLabel)
                art.addAttribute(att)
            else:
                if self.filesFound < self.nbrOfFilesToProcessPerThread:
                    vtLabel = self.processVirusTotalApi(file)
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, VirusTotalFileIngestModuleFactory.moduleName, vtLabel)
                    time.sleep(self.timeToPause)
                    
        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(VirusTotalFileIngestModuleFactory.moduleName, BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));
        return IngestModule.ProcessResult.OK
        
        
    def processVirusTotalApi(self, file):
        hash = file.getMd5Hash()
        hash = hash.strip()
        if not hash:
            return "VirusTotal Bad Hash"
        elif not re.findall(r"([a-fA-F\d]{32}", hash):
            return "VirusTotal Bad Hash"
        
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": hash, "apikey": self.apiKey}
        
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        if response.code == 200:
            try:
                response_dict = loads(response.read())
                vtCode = response_dict.get("response_code")
                if vtCode == 1:
                    matches = response_dict.get("positives")
                    if matches > 0:
                        lock = threading.RLock()
                        with lock:
                            # TODO
                            outfile = open("D:\Autopsy\FoundHash.txt", "a+")
                            outfile.write("\n\n\n")
                            outfile.write("Virus Found for file : ")
                            outfile.write(file.getName())
                            outfile.write("\n")
                            prettyPrintDict(response_dict, outfile, 1, 0)
                            outfile.close()
                        return "VirusTotal Detected Virus"
                    else:
                        if self.createOutputForKnown:
                            lock = threading.RLock()
                            with lock:
                                # TODO
                                outfile = open("D:\Autopsy\FoundKnownHash.txt",  "a+")
                                outfile.write("\n\n\n")
                                outfile.write("VT Known file : ")
                                outfile.write(file.getName())
                                outfile.write("\n")
                                prettyPrintDict(response_dict, 1, 0)
                                outfile.close()
                            return "VirusTotal No Match"
                            
                elif vtCode == 0:
                    return "Unknown To VirusTotal"
            except:
                return "VirusTotal bad data"
        else:
            return "VirusTotal Quota Error"
            
            
    def shutDown(self):
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, VirusTotalFileIngestModuleFactory.moduleName, str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)
            
                
            
