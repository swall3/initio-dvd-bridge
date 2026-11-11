using System;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

internal static class TrayHost {
    [STAThread]
    private static int Main(string[] args) {
        string root=AppDomain.CurrentDomain.BaseDirectory;
        string python=Path.Combine(root,"runtime","python.exe");
        bool hidden=false;
        try {
            for(int i=0;i<args.Length;i++) {
                if(args[i]=="--hidden") hidden=true;
                else if(args[i]=="--python" && i+1<args.Length) python=Path.GetFullPath(args[++i]);
                else throw new ArgumentException("Unknown DVD Controls option.");
            }
            string script=Path.Combine(root,"work","initio","dvd_tray.ps1");
            if(!File.Exists(script)||!File.Exists(python)) throw new FileNotFoundException("DVD Controls installation is incomplete.");
            Environment.SetEnvironmentVariable("PSModulePath",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell","v1.0","Modules"));
            var initial=InitialSessionState.CreateDefault();
            initial.ExecutionPolicy=Microsoft.PowerShell.ExecutionPolicy.Bypass;
            using(var runspace=RunspaceFactory.CreateRunspace(initial)) {
                runspace.ApartmentState=ApartmentState.STA;
                runspace.ThreadOptions=PSThreadOptions.UseCurrentThread;
                runspace.Open();
                using(var powershell=PowerShell.Create()) {
                    powershell.Runspace=runspace;
                    powershell.AddCommand(script).AddParameter("Python",python).AddParameter("Hidden",hidden);
                    powershell.Invoke();
                    if(powershell.HadErrors) throw new Exception(powershell.Streams.Error[0].ToString());
                }
            }
            return 0;
        } catch(Exception error) {
            MessageBox.Show(error.Message,"DVD Controls",MessageBoxButtons.OK,MessageBoxIcon.Error);
            return 1;
        }
    }
}
