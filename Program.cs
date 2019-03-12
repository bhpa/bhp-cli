using Bhp.Shell;
using Bhp.Wallets;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Xml.Linq;

namespace Bhp
{
    static class Program
    {
        internal static Wallet Wallet;

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            using (FileStream fs = new FileStream("error.log", FileMode.Create, FileAccess.Write, FileShare.None))
            using (StreamWriter w = new StreamWriter(fs))
                if (e.ExceptionObject is Exception ex)
                {
                    PrintErrorLogs(w, ex);
                }
                else
                {
                    w.WriteLine(e.ExceptionObject.GetType());
                    w.WriteLine(e.ExceptionObject);
                }
        }

        static void Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            var bufferSize = 1024 * 67 + 128;
            Stream inputStream = Console.OpenStandardInput(bufferSize);
            Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, bufferSize));

            //if (UpdateVersion()) return;

            var mainService = new MainService();
            mainService.Run(args);
        }

        private static void PrintErrorLogs(StreamWriter writer, Exception ex)
        {
            writer.WriteLine(ex.GetType());
            writer.WriteLine(ex.Message);
            writer.WriteLine(ex.StackTrace);
            if (ex is AggregateException ex2)
            {
                foreach (Exception inner in ex2.InnerExceptions)
                {
                    writer.WriteLine();
                    PrintErrorLogs(writer, inner);
                }
            }
            else if (ex.InnerException != null)
            {
                writer.WriteLine();
                PrintErrorLogs(writer, ex.InnerException);
            }
        }

        static string download_path;
        private static bool UpdateVersion()
        {
            XDocument xdoc = null;
            WebClient web = new WebClient();
            string download_url;

            try
            {
                xdoc = XDocument.Load("https://bhpa.io/client/update.xml");
            }
            catch { }
            if (xdoc != null)
            {
                Version version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                Version minimum = Version.Parse(xdoc.Element("update").Attribute("minimum").Value);
                if (version < minimum)
                {
                    Version latest = Version.Parse(xdoc.Element("update").Attribute("latest").Value);
                    XElement release = xdoc.Element("update").Elements("release").First(p => p.Attribute("version").Value == latest.ToString());
                    download_url = release.Attribute("file").Value;
                    download_path = "Release.zip";
                    web.DownloadFile(new Uri(download_url), download_path);
                    UpdateFiles();

                    return true;
                }
            }
            return false;
        }

        private static void UpdateFiles()
        {
            DirectoryInfo di = new DirectoryInfo("update");
            if (di.Exists) di.Delete(true);
            di.Create();
            ZipFile.ExtractToDirectory(download_path, di.Name);
            FileSystemInfo[] fs = di.GetFileSystemInfos();
            if (fs.Length == 1 && fs[0] is DirectoryInfo)
            {
                ((DirectoryInfo)fs[0]).MoveTo("update2");
                di.Delete();
                Directory.Move("update2", di.Name);
            }
            //File.WriteAllBytes("update.bat", Resources.UpdateBat);
            Process.GetCurrentProcess().Close();
            Process.Start("update.bat");
        }
    }
}
