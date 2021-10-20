package persistent_autopsy;
import java.util.List;
import java.util.logging.Level;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.casemodule.services.Services;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestModule;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.FsContent;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestMessage;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.TskData;
class SampleDataSourceIngestModule implements DataSourceIngestModule {
    private final boolean skipKnownFiles;
    private IngestJobContext context = null;
    SampleDataSourceIngestModule(SampleModuleIngestJobSettings settings) {
        this.skipKnownFiles = settings.skipKnownFiles();
    }
    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;
    }
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        if (context.dataSourceIngestIsCancelled()) {
            return IngestModule.ProcessResult.OK;
        }
        // There are two tasks to do.
        progressBar.switchToDeterminate(2);
        Case autopsyCase = Case.getCurrentCase();
        SleuthkitCase sleuthkitCase = autopsyCase.getSleuthkitCase();
        Services services = new Services(sleuthkitCase);
        FileManager fileManager = services.getFileManager();
        try {
            // Get count of files with .doc extension.
            long fileCount = 0;
            List<AbstractFile> docFiles = fileManager.findFiles(dataSource, "%.doc");
            for (AbstractFile docFile : docFiles) {
                if (!skipKnownFiles || docFile.getKnown() != TskData.FileKnown.KNOWN) {
                    ++fileCount;
                }
            }
            progressBar.progress(1);
            if (context.dataSourceIngestIsCancelled()) {
                return IngestModule.ProcessResult.OK;
            }
            // Get files by creation time.
            long currentTime = System.currentTimeMillis() / 1000;
            long minTime = currentTime - (14 * 24 * 60 * 60); // Go back two weeks.
            List<AbstractFile> otherFiles = fileManager.findFiles(dataSource, "crtime > " + minTime);
            for (AbstractFile otherFile : otherFiles) {
                if (!skipKnownFiles || otherFile.getKnown() != TskData.FileKnown.KNOWN) {
                    ++fileCount;
                }
            }
            progressBar.progress(1);
            if (context.dataSourceIngestIsCancelled()) {
                return IngestModule.ProcessResult.OK;
            }
            // Post a message to the ingest messages in box.
            String msgText = String.format("Found %d files", fileCount);
            IngestMessage message = IngestMessage.createMessage(
                    IngestMessage.MessageType.DATA,
                    SampleIngestModuleFactory.getModuleName(),
                    msgText);
            IngestServices.getInstance().postMessage(message);
            return IngestModule.ProcessResult.OK;
        } catch (TskCoreException ex) {
            IngestServices ingestServices = IngestServices.getInstance();
            Logger logger = ingestServices.getLogger(SampleIngestModuleFactory.getModuleName());
            logger.log(Level.SEVERE, "File query failed", ex);
            return IngestModule.ProcessResult.ERROR;
        }
    }
}