import jarray
import inspect
import os
import shutil
import ntpath

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



# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class AutoRunsIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Autorun Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Extract Run Keys To Look For Files that Execute on Startup"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def hasIngestJobSettingsPanel(self):
        return False

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return AutoRunsIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class AutoRunsIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(AutoRunsIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
 
    # Where any setup and configuration is done
    def startUp(self, context):
        self.context = context
        self.registryNTUserRunKeys = ('Software/Microsoft/Windows/CurrentVersion/Run', 'Software/Microsoft/Windows/CurrentVersion/RunOnce', 'Software/Microsoft/Windows/CurrentVersion/Explorer/User Shell Folders', 'Software/Microsoft/Windows/CurrentVersion/Explorer/Shell Folders')
        self.registrySoftwareRunKeys = ('Microsoft/Windows/CurrentVersion/Run', 'Microsoft/Windows/CurrentVersion/RunOnce', 'Microsoft/Windows/CurrentVersion/Explorer/Shell Folders', 'Microsoft/Windows/CurrentVersion/Explorer/User Shell Folders')
        self.registryKeysFound = []

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Hive files to extract        
        filesToExtract = ("NTUSER.DAT", "SOFTWARE", "%/Start Menu/Programs/Startup/", "%/System32/Tasks/", "%/Windows/Prefetch/", "%/Windows/System32/winevt/Logs/")
        
        # Create ExampleRegistry directory in temp directory, if it exists then continue on processing		
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "AutorunsResults")
        self.log(Level.INFO, "create Directory " + tempDir)
        try:
            os.mkdir(tempDir)
        except:
            self.log(Level.INFO, "AutorunsResult Directory already exists " + tempDir)

        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Look for files to process
        startupcount = 0
        prefetchcount = 0
        taskscount = 0
        filecount = 0
        for fileName in filesToExtract:
            if fileName == "%/Start Menu/Programs/Startup/":
                files = fileManager.findFiles(dataSource, "%", fileName)
            elif fileName == "%/System32/Tasks/":
                files = fileManager.findFiles(dataSource, "%", fileName)
            elif fileName == "%/Windows/Prefetch/":
                files = fileManager.findFiles(dataSource, "%", fileName)
            elif fileName == "%/Windows/System32/winevt/Logs/":
                files = fileManager.findFiles(dataSource, "%", fileName)
            else:
                files = fileManager.findFiles(dataSource, fileName)
            numFiles = len(files)

            for file in files:
            
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                # Check path to only get the hive files in the config directory and no others
                if ((file.getName() == 'SOFTWARE') and (file.getParentPath().upper() == '/WINDOWS/SYSTEM32/CONFIG/') and (file.getSize() > 0)):    
                    # Save the file locally in the temp folder. 
                    self.writeHiveFile(file, file.getName(), tempDir)
                  
                    # Process this file looking thru the run keys
                    self.processSoftwareHive(os.path.join(tempDir, file.getName()), file)
                    
                elif ((file.getName() == 'NTUSER.DAT') and ('/USERS' in file.getParentPath().upper()) and (file.getSize() > 0)):
                # Found a NTUSER.DAT file to process only want files in User directories
                    # Filename may not be unique so add file id to the name                    
                    fileName = str(file.getId()) + "-" + file.getName()                    
                    
                    # Save the file locally in the temp folder.
                    self.writeHiveFile(file, fileName, tempDir)
     
                    # Process this file looking thru the run keys
                    self.processNTUserHive(os.path.join(tempDir, fileName), file)

                else:
                    if fileName == "%/Windows/Prefetch/":
                        prefetchcount += 1                        
                        attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                      AutoRunsIngestModuleFactory.moduleName,
                                                      "Prefetch"))
                        arts = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT, Score.SCORE_LIKELY_NOTABLE,
                                         None, "Prefetch files", None, attrs).getAnalysisResult()                        
                    elif fileName == "%/System32/Tasks/":
                        if file.getName() == "." or  file.getName() == "..":
                            continue
                        else:
                            taskscount += 1
                            attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                          AutoRunsIngestModuleFactory.moduleName,
                                                          "Tasks"))
                            arts = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT, Score.SCORE_LIKELY_NOTABLE,
                                             None, "Scheduled tasks", None, attrs).getAnalysisResult()
                    elif fileName == "%/Windows/System32/winevt/Logs/":
                        taskscount += 1
                        attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                      AutoRunsIngestModuleFactory.moduleName,
                                                      "Window Event logs"))
                        arts = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT, Score.SCORE_LIKELY_NOTABLE,
                                         None, "Window Event Logs", None, attrs).getAnalysisResult()
                    else:
                        if file.getName() == ".." or file.getName() == ".":
                            continue
                        else:
                            startupcount += 1                            
                            attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                          AutoRunsIngestModuleFactory.moduleName,
                                                          "Startup"))
                            arts = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT, Score.SCORE_LIKELY_NOTABLE,
                                             None, "Auto run files", None, attrs).getAnalysisResult()                        
                    filecount += 1
                    
                    try:
                        blackboard.postArtifact(arts, AutoRunsIngestModuleFactory.moduleName)
                    except Blackboard.BlackboardException as e:
                        self.log(Level.SEVERE, "Error indexing artifact " + arts.getDisplayName())
                        
                    
 
       
        # Setup Artifact and Attributes
        artType = skCase.getArtifactType("TSK_AUTO_RUN_KEYS")
        if not artType:
            try:
                artType = skCase.addBlackboardArtifactType( "TSK_AUTO_RUN_KEYS", "Autorun keys")
            except:		
                self.log(Level.WARNING, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
          
        try:           
           attributeIdProgramName = skCase.addArtifactAttributeType("TSK_PROGRAM_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Program Name")
        except:		
           self.log(Level.INFO, "Attributes Creation Error, TSK_PROGRAM_NAME, May already exist. ")
        try:           
           attributeIdRunKeyValue = skCase.addArtifactAttributeType("TSK_FILE_LOCATION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Location")
        except:		           
           self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_LOCATION, May already exist. ")
        try:
           attributeIdRegKeyLoc = skCase.addArtifactAttributeType("TSK_REG_KEY_LOCATION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Registry Key Location")
        except:		
           self.log(Level.INFO, "Attributes Creation Error, TSK_REG_KEY_LOCATION, May already exist. ")
        
        attributeIdProgramName = skCase.getAttributeType("TSK_PROGRAM_NAME")
        attributeIdRunKeyValue = skCase.getAttributeType("TSK_FILE_LOCATION")
        attributeIdRegKeyLoc = skCase.getAttributeType("TSK_REG_KEY_LOCATION")
        
        moduleName = AutoRunsIngestModuleFactory.moduleName
        
        # RefistryKeysFound is a list that contains a list with the following records abstractFile, Registry Key Location, Key Name, Key value
        for registryKey in self.registryKeysFound:
            # self.log(Level.INFO, "Creating artifact for registry key with path: " + registryKey[1] + " and key: " + registryKey[2])
            art = registryKey[0].newDataArtifact(artType, Arrays.asList(
                BlackboardAttribute(attributeIdRegKeyLoc, moduleName, registryKey[1]),                
                BlackboardAttribute(attributeIdProgramName, moduleName, registryKey[2]),
                BlackboardAttribute(attributeIdRunKeyValue, moduleName, registryKey[3])
            ))
            
            # index the artifact for keyword search
            try:
                blackboard.postArtifact(art, moduleName)
            except Blackboard.BlackboardException as ex:
                self.log(Level.SEVERE, "Unable to index blackboard artifact " + str(art.getArtifactTypeName()), ex)
        
		#Clean up module directory and files
        try:
            shutil.rmtree(tempDir)		
        except:
            self.log(Level.INFO, "removal of directory tree failed " + tempDir)
 
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "AutoRuns", " Autoruns Files Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)
        # message1 = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            # "AutoRuns", " Found %d interesting files" % filecount)
        # IngestServices.getInstance().postMessage(message1)
        message1 = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "AutoRuns", " Found %d startup files" % startupcount)
        IngestServices.getInstance().postMessage(message1)
        message2 = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "AutoRuns", " Found %d scheduled task files" % taskscount)
        IngestServices.getInstance().postMessage(message2)
        message3 = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "AutoRuns", " Found %d prefetch files" % prefetchcount)
        IngestServices.getInstance().postMessage(message3)

        return IngestModule.ProcessResult.OK                

    def writeHiveFile(self, file, fileName, tempDir):
        # Write the file to the temp directory.  
        filePath = os.path.join(tempDir, fileName)
        ContentUtils.writeToFile(file, File(filePath))
    

    def processSoftwareHive(self, softwareHive, abstractFile):
        # Open the registry hive file 
        softwareRegFile = RegistryHiveFile(File(softwareHive))
        for runKey in self.registrySoftwareRunKeys:
            currentKey = self.findRegistryKey(softwareRegFile, runKey)
            if currentKey and len(currentKey.getValueList()) > 0:
                skValues = currentKey.getValueList()
                for skValue in skValues:
                    regKey = []
                    regKey.append(abstractFile)
                    regKey.append(runKey)
                    skName = skValue.getName()
                    skVal = skValue.getValue()
                    regKey.append(str(skName))
                    regKey.append(skVal.getAsString())
                    self.registryKeysFound.append(regKey)
                    

    def processNTUserHive(self, ntuserHive, abstractFile):
    
        # Open the registry hive file 
        ntuserRegFile = RegistryHiveFile(File(ntuserHive))
        for runKey in self.registryNTUserRunKeys:
            currentKey = self.findRegistryKey(ntuserRegFile, runKey)
            if currentKey and len(currentKey.getValueList()) > 0:
                skValues = currentKey.getValueList()
                for skValue in skValues:
                    regKey = []
                    regKey.append(abstractFile)
                    regKey.append(runKey)
                    skName = skValue.getName()
                    skVal = skValue.getValue()
                    regKey.append(str(skName))
                    regKey.append(skVal.getAsString())
                    self.registryKeysFound.append(regKey)

    def findRegistryKey(self, registryHiveFile, registryKey):
        # Search for the registry key
        rootKey = registryHiveFile.getRoot()
        regKeyList = registryKey.split('/')
        currentKey = rootKey
        try:
            for key in regKeyList:
                currentKey = currentKey.getSubkey(key) 
            return currentKey
        except Exception as ex:
            # Key not found
            self.log(Level.SEVERE, "registry key parsing issue:", ex)
            return None        
        

