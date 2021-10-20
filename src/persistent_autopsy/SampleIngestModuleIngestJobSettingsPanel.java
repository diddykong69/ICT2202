package persistent_autopsy;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;
public class SampleIngestModuleIngestJobSettingsPanel extends IngestModuleIngestJobSettingsPanel {
    public SampleIngestModuleIngestJobSettingsPanel(SampleModuleIngestJobSettings settings) {
        initComponents();
        customizeComponents(settings);
    }
    private void customizeComponents(SampleModuleIngestJobSettings settings) {
        skipKnownFilesCheckBox.setSelected(settings.skipKnownFiles());
    }
    @Override
    public IngestModuleIngestJobSettings getSettings() {
        return new SampleModuleIngestJobSettings(skipKnownFilesCheckBox.isSelected());
    }
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {
        skipKnownFilesCheckBox = new javax.swing.JCheckBox();
        org.openide.awt.Mnemonics.setLocalizedText(skipKnownFilesCheckBox, org.openide.util.NbBundle.getMessage(SampleIngestModuleIngestJobSettingsPanel.class, "SampleIngestModuleIngestJobSettingsPanel.skipKnownFilesCheckBox.text")); // NOI18N
        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(skipKnownFilesCheckBox)
                .addContainerGap(255, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(skipKnownFilesCheckBox)
                .addContainerGap(270, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox skipKnownFilesCheckBox;
    // End of variables declaration//GEN-END:variables
}