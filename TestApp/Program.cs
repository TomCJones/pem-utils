// PemUtil Test App - tomjones.us
// Only for use in Windows in a single thread environment

using System;
using System.IO;
using PemUtils;


namespace TestApp
{
    
    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine("PemUtil test app Starting");
            string rawSchema = "";
            string cPath = "CERTIFICATE.txt";
            DynamicDictionary schemObj = new DynamicDictionary();

            using (StreamReader sr = new StreamReader(cPath))
            {
                rawSchema = sr.ReadToEnd();
            }
            //    var fileDialog = new OpenFileDialog();
            Console.Write("Enter file name of PEM file:");
            string path = Console.ReadLine().Trim('"');  // to support cut and paste from file explorer
            if (!string.IsNullOrWhiteSpace(path) )
            {
                try
                { 
                    var stream = File.OpenRead(path);
                    PemReader pemReader = new PemReader(stream);
 
                    string jsonAsn = pemReader.ReadAsJson(path, rawSchema);
                    Console.Write(jsonAsn);
                }
                catch (Exception ex)
                {
                     Console.WriteLine("File did not contain a well formated PEM stucture - exception " + ex.Message);
                }
            }
            else
            {
                Console.WriteLine("File could not be opened!");
            }
            Console.WriteLine("PemUtil test app Ended");
        }
    }
}
