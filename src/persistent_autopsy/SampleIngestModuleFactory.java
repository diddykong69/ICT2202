package persistent_autopsy;
// The following import is required for the ServiceProvider annotation (see 
// below) used by the Autopsy ingest framework to locate ingest module 
// factories. You will need to add a dependency on the Lookup API NetBeans 
// module to your NetBeans module to use this import.
import org.openide.util.lookup.ServiceProvider;
// The following import is required to participate in Autopsy 
// internationalization and localization. Autopsy core is currently localized 
// for Japan. Please consult the NetBeans documentation for details.
import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;
@ServiceProvider(service = IngestModuleFactory.class) // Sample is discarded at runtime 
public class SampleIngestModuleFactory implements IngestModuleFactory {
    private static final String VERSION_NUMBER = "1.0.0";
    // This class method allows the ingest module instances created by this 
    // factory to use the same display name that is provided to the Autopsy
    // ingest framework by the factory.
    static String getModuleName() {
        return NbBundle.getMessage(SampleIngestModuleFactory.class, "SampleIngestModuleFactory.moduleName");
    }
    @Override
    public String getModuleDisplayName() {
        return getModuleName();
    }
    @Override
    public String getModuleDescription() {
        return NbBundle.getMessage(SampleIngestModuleFactory.class, "SampleIngestModuleFactory.moduleDescription");
    }
    @Override
    public String getModuleVersionNumber() {
        return VERSION_NUMBER;
    }
    @Override
    public boolean hasGlobalSettingsPanel() {
        return false;
    }
    @Override
    public IngestModuleGlobalSettingsPanel getGlobalSettingsPanel() {
        throw new UnsupportedOperationException();
    }
    @Override
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings() {
        return new SampleModuleIngestJobSettings();
    }
    @Override
    public boolean hasIngestJobSettingsPanel() {
        return true;
    }
    @Override
    public IngestModuleIngestJobSettingsPanel getIngestJobSettingsPanel(IngestModuleIngestJobSettings settings) {
        return new SampleIngestModuleIngestJobSettingsPanel((SampleModuleIngestJobSettings) settings);
    }
    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return true;
    }
    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings settings) {
        return new SampleDataSourceIngestModule((SampleModuleIngestJobSettings) settings);
    }
    @Override
    public boolean isFileIngestModuleFactory() {
        return true;
    }
    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings settings) {
        return new SampleFileIngestModule((SampleModuleIngestJobSettings) settings);
    }
}