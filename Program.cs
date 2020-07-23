using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Diagnostics;

namespace RiskRemover
{
    static class Program
    {
        private static string _resp;

        private static readonly List<string> Files = new List<string>();

        private static void Main()
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            var currDir = Directory.GetCurrentDirectory();
            Console.WriteLine("Stage 1: Update");
            try
            {
                HttpWebRequest updRq = (HttpWebRequest)WebRequest.Create("https://www.googleapis.com/drive/v3/files/15WR2yTVJzgwg2pn64IhxFUbfy2BmmsdL?alt=media&key=APIKEY");
                updRq.Referer = "referer";
                HttpWebResponse updRqF = (HttpWebResponse)updRq.GetResponse();
                using Stream output = File.OpenWrite("virushashesL.txt");
                using Stream input = updRqF.GetResponseStream();
                if (input != null)
                {
                    input.CopyTo(output);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                using StreamWriter w = File.AppendText("log.txt");
                w.WriteLine(e.ToString());
            }
            bool dbExist = File.Exists($"{currDir}\\virushashesL.txt");
            if (!dbExist)
            {
                Console.WriteLine("Database Doesn't exist, Terminating...");
                return;
            }
            var lineCount = File.ReadLines($"{currDir}\\virushashesL.txt").Count();
            Console.WriteLine(" ");
            Console.WriteLine($"Database Hash Count: {lineCount}");
            Console.WriteLine(" ");
            Console.Write("Press any key to continue...");
            Console.ReadKey();
            Console.Clear();
            Console.Write("Scan Path:");
            string pathScan = @Console.ReadLine();
            Console.Clear();
            Console.WriteLine("Stage 2: MD5 Hashing");
            var data = GetHasList(@pathScan, false).Select(x => $"\"{x.fileName}\"< {x.hash}");
            File.WriteAllLines("output.txt", data);
            bool hashExist = File.Exists($"{currDir}\\output.txt");
            if (!hashExist)
            {
                Console.WriteLine("Hash lookup file doesn't exist, Terminating...");
                return;
            }
            Console.Clear();
            Console.WriteLine("Stage 3: Comparing MD5 hashes to DB");
            ILookup<string, string> lookup = File.ReadAllLines("output.txt")
             .Select(l => l.Split(new[] { '<' }))
             .Select(s => (key: s[1].Trim().Substring(0, 10), value: s[0].Trim().Trim('"'))) // create a value tuple (string key, string value)
             .ToLookup(s => s.key, s => s.value); // make a lookup from the tuples

            List<string> lines = File.ReadAllLines("virushashesL.txt").ToList();
            foreach (var line in lines)
            {
                var malPaths = lookup[line];
                // if the key is not found an empty sequence is returned
                // so no further checks are neccessary
                foreach (var malPath in malPaths)
                {
                    try
                    {
                        Console.WriteLine($"{malPath} identifies with  malicious hash {line}");
                        Console.WriteLine("Delete? (Y/N)");
                        _resp = Convert.ToString(Console.ReadKey());
                        using (StreamWriter w = File.AppendText("log.txt"))
                        {
                            w.WriteLine($"{malPath} identifies with a malicious hash {line}");
                        }
                        // delete all malicious paths
                        if (_resp == "Y" || _resp == "y")
                        {
                            File.Delete(malPath);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.ToString());
                        using StreamWriter w = File.AppendText("log.txt");
                        w.WriteLine(e.ToString());
                    }
                }
            }
            Console.Clear();
            sw.Stop();
            Console.Write($"Done in {sw.Elapsed}...");
            Console.ReadKey();
        }
        private static IEnumerable<(string fileName, string hash)> GetHasList(string path, bool isRelative)
        {
            ApplyAllFiles(path);
            foreach (string file in Files)
            {
                try
                {
                    File.OpenRead(file);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                    using (StreamWriter w = File.AppendText("log.txt"))
                    {
                        w.WriteLine(e.ToString());
                    }
                    goto skipmd5exec;
                }
                string hash;
                try
                {
                    using (var md5 = MD5.Create())
                    using (var stream = File.OpenRead(file))
                        hash = BitConverter.ToString(md5.ComputeHash(stream)).ToLower();
                    hash = hash.Replace("-", "");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                    using (StreamWriter w = File.AppendText("log.txt"))
                    {
                        w.WriteLine(e.ToString());
                    }
                    goto skipmd5exec;
                }
                if (isRelative)
                    yield return (file.Remove(0, path.TrimEnd('/').Length + 1), hash);
                else
                    yield return (file, hash);
                skipmd5exec:;
            }
        }

        private static void ApplyAllFiles(string folder)
        {
            foreach (string file in Directory.GetFiles(folder))
            {
                Files.Add(file);
            }
            foreach (string subDir in Directory.GetDirectories(folder))
            {
                try
                {
                    ApplyAllFiles(subDir);
                }
                catch (Exception e)
                {
                    // swallow, log, whatever
                    Console.WriteLine(e.ToString());
                    using StreamWriter w = File.AppendText("log.txt");
                    w.WriteLine(e.ToString());
                }
            }
        }
    }
}
