fn main() {
    slint_build::compile("ui/main.slint").expect("compile Slint user interface");

    #[cfg(windows)]
    {
        let manifest = r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
      <supportedOS Id="{4f476546-9374-4f8f-9a2a-531e8f92e65a}" />
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#;
        winresource::WindowsResource::new()
            .set_manifest(manifest)
            .set("FileDescription", "OBR Mod Updater")
            .set("ProductName", "Oblivion Remaster Mod Updater Tool")
            .set("OriginalFilename", "OBR Mod Updater.exe")
            .compile()
            .expect("compile Windows application resources");
    }
}
