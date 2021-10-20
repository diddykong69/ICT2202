/*
 * Sample module ingest job settings panel in the public domain.  
 * Feel free to use this as a template for your module ingest job settings
 * panels.
 * 
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *
 *  This is free and unencumbered software released into the public domain.
 *  
 *  Anyone is free to copy, modify, publish, use, compile, sell, or
 *  distribute this software, either in source code form or as a compiled
 *  binary, for any purpose, commercial or non-commercial, and by any
 *  means.
 *  
 *  In jurisdictions that recognize copyright laws, the author or authors
 *  of this software dedicate any and all copyright interest in the
 *  software to the public domain. We make this dedication for the benefit
 *  of the public at large and to the detriment of our heirs and
 *  successors. We intend this dedication to be an overt act of
 *  relinquishment in perpetuity of all present and future rights to this
 *  software under copyright law.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 *  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *  OTHER DEALINGS IN THE SOFTWARE. 
 */
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