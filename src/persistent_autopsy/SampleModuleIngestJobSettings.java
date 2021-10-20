package persistent_autopsy;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
public class SampleModuleIngestJobSettings implements IngestModuleIngestJobSettings {
    private static final long serialVersionUID = 1L;
    private boolean skipKnownFiles = true;
    SampleModuleIngestJobSettings() {
    }
    SampleModuleIngestJobSettings(boolean skipKnownFiles) {
        this.skipKnownFiles = skipKnownFiles;
    }
    @Override
    public long getVersionNumber() {
        return serialVersionUID;
    }    
    void setSkipKnownFiles(boolean enabled) {
        skipKnownFiles = enabled;
    }
    boolean skipKnownFiles() {
        return skipKnownFiles;
    }
}