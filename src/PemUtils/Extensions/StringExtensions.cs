using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PemUtils
{
    internal static class StringExtensions
    {
        public static string RemoveWhitespace(this string input)
        {
            return Regex.Replace(input, @"\s+", string.Empty);
        }
        public static int StringType(this string input)
        {
            int iType = 18;  // default is numeric - the most restrictive
            int iTemp = 0;
            if (string.IsNullOrEmpty(input)) return 0;
            if (input.Length < 1) return 0;
            foreach (char c in input)
            {
                iTemp = (int)c;
                if (iTemp < 33 || iTemp > 126) return 28;  // i.e. treat string as Unicode
                if (iTemp < 48 || iTemp > 58)               // numbers never change state
                {
                    iType = 19;                             // temp, just call it Printable string
                }
            }
            return iType;
        }
        public static string[] AsnSplit(this string input)
        {
            int iStart = 0;
            bool bWhite = true;
            bool bComment = false;
            bool bracket = false;
            bool bCap = false;
            bool bCommand = false;
            List<string> resList = new List<string>();
            int i = 0;
            foreach (char c in input)
            {
                if (bComment)
                {
                    if (c == '\n') { bComment = false; }
                }
                else
                {
                    if (bCommand && c == '\n')  // need to collect all tokens in a command and then terminate the command
                    {
                        string iTest = input.Substring(iStart, i - iStart).Trim();
                        if (!string.IsNullOrWhiteSpace(iTest))  // command must have a target, or the \n should be ignored
                        {
                            resList.Add("::=");
                            resList.Add(iTest);
                            resList.Add("tERM");
                            bCommand = false;
                            bWhite = true;
                        }

                    }
                    if (c == '{')
                    {
                        if (bracket)
                        {
                            throw new InvalidOperationException("close brackets w/o open bracket");
                        }
                        else
                        {
                            if (!bWhite)
                            {
                                resList.Add("::=");
                                string iTest = input.Substring(iStart, i - iStart).TrimEnd();
                                resList.Add(iTest);
                            }
                            resList.Add("{");
                            bCommand = false;
                            bracket = true;
                            bWhite = true;
                        }
                    }
                    else if (c == '}')
                    {
                        if (bracket)
                        {
                            if (!bWhite)
                            {
                                string iTest = input.Substring(iStart, i - iStart);
                                resList.Add(iTest);
                            }
                            resList.Add("}");
                            bracket = false;
                            bWhite = true;
                        }
                        else
                        {
                            throw new InvalidOperationException("two open brackets w/o close bracket");
                        }
                    }
                    else
                    {
                        if (bCommand)
                        {
                        }
                        else
                        {
                            if (bWhite)
                            {
                                if (!Char.IsWhiteSpace(c)) { bWhite = false; iStart = i; }
                            }
                            else
                            {
                                if (Char.IsWhiteSpace(c))
                                {
                                    string iTest = input.Substring(iStart, i - iStart).TrimEnd();
                                    if (iTest == "--") { bComment = true; bWhite = true; }
                                    else if (iTest == "::=")
                                    {
                                        bCommand = true;
                                        //                  resList.Add(iTest);
                                        iStart = i;  // this prevents dups
                                    }
                                    else
                                    {
                                        bCap = iTest.All(char.IsLetter) && iTest.All(char.IsUpper);
                                        if (!bCap || c == '\n')
                                        {
                                            if (iTest.EndsWith(','))  // a terminating comma is a syntax element of its own
                                            {
                                                resList.Add(iTest.TrimEnd(','));
                                                resList.Add(",");
                                            }
                                            else resList.Add(iTest);
                                            bWhite = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                i++;
            }

            string[] res = resList.ToArray();
            return res;
        }
    }
}
