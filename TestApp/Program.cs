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
     //       string pemCode = "-----";
            string path = "";
            //    var fileDialog = new OpenFileDialog();
            Console.Write("Enter file name of PEM file:");
            path = Console.ReadLine().Trim('"');
            if (!string.IsNullOrWhiteSpace(path) )
            {
                try
                { 
                    var stream = File.OpenRead(path);
                    PemReader pemReader = new PemReader(stream);
                    //                  var rsaParameters = pemReader.ReadRsaKey();
                    //                  string fu = rsaParameters.ToString();

                    string jsonAsn = pemReader.ReadAsJson();
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
