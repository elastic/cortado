using System;
using Microsoft.Win32;
using System.IO;

// https://github.com/mvelazc0/PurpleSharp/blob/master/PurpleSharp/Simulations/PersistenceHelper.cs
class Seat
{
    static void Main()
    {
        string key = @"RTA";
        RegistryKey registryKey1 = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
        registryKey1.SetValue(key, @"Test");
        Console.WriteLine(@"Created Regkey: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"+ key + @" - Test");
        registryKey1.DeleteValue(key);
        Console.WriteLine(@"Deleted RegKey : HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"+key);
        
        string startUpFolderPath = Environment.GetFolderPath(Environment.SpecialFolder.Startup) + "\\test.exe";
        Console.WriteLine(startUpFolderPath);
        using(File.Create(startUpFolderPath)) {};
        Console.WriteLine(@"Created file on the startupe folder: test.exe");
        File.Delete(startUpFolderPath);
        Console.WriteLine(@"Deleted file: test.exe");
    }
}