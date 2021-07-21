using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace PemUtils
{
    public class CddlHandler
    {
        public Dictionary<string, string> baseTypes = new Dictionary<string, string>
            {
                {" int", "Positive or negative integer" },
                {" uint", " Positive integer" },
                {" bstr", " Byte string" },
                {" tstr", " Text string" },
                {" bool", " Boolean" },
                {" nil", " Nil/Null value" },
                {" float", " Floating point value" },
                {" any", " Any single element" }
            };
        public readonly string _Name;
        public readonly string _RawSchema;
        private dynamic entry = new DynamicDictionary();
        public string[] iArray;
        private Stack<CddlState> stateStack = new Stack<CddlState>();
        public CddlHandler(string cName, string rawSchema)
        {
            _Name = cName;
            _RawSchema = rawSchema;
        }
        // load the token from the raw data into an array of strings which are tokens
        public string[] InitalLoad()
        {
            string[] res = new string[] { "Intial Load failed" };
            // the following is a finite state machine in the context of the finite input string.
            // The state is composed of the iState, cType, label and push down stack of those 3 values.
            int iState = 0;
            string cType = "";
            string label = "";
            string seqToken = "";
            iArray = _RawSchema.AsnSplit();  //the input string split into tpkens
            string[] seqValues = new string[3];
            Dictionary<string, string[]> o = null;

            foreach (string nStr in iArray.Where(i => !string.IsNullOrWhiteSpace(i)))
            {
                switch (iState)
                {
                    case 0:  // initial state waiting for symbol
                        if (nStr.StringType() == 19)
                        {
                            label = nStr;
                            iState = 1;  
                        }
                        break;

                    case 1:   // 1st symbol recieved
                        if (nStr == "::=")           // is the label being equated to something?
                        {
                            iState = 2;
                        }

                        else if (nStr.StringType() == 19)  // is the label pointing to a class?
                        {
                            // add to the current dictionary at this point in the stack
                            iState = 0;
                        }
                        break;

                    case 2:  // waiting for what the symbol defintion is
                        cType = nStr;
                        iState = 3;
                        break;

                    case 3:
                        if (nStr == "{")
                        {
                            o = (Dictionary<string, string[]>)Activator.CreateInstance(typeof(Dictionary<string, string[]>));
                            o.Add("_TYPE", new string[3] { cType, "", "" });
                            entry.Add(label, o); 
                            iState = 4;
                        }
                        else if (nStr.StringType() == 19)
                        {
                            if (nStr == "tERM")
                            {
                                entry.Add(label, cType);
                                iState = 0;
                            }
                        }
                        else { throw new InvalidOperationException("Expected a valid token.  Received " + nStr); }

                        break;
                    case 4:
                        if (nStr.StringType() == 19)
                        {
                            seqToken = nStr;
                            seqValues[0] = seqValues[1] = seqValues[2] = "";
                            iState = 5;
                        }
                        else
                        {
                            throw new InvalidOperationException("parsing error in sequence named " + seqToken);
                        }
                        break;

                    case 5:
                        if (nStr == ",")
                        {
                            o.Add(seqToken, seqValues);
                            iState = 4;  // go look for next token
                        }
                        else if (nStr == "}")
                        {
                            o.Add(seqToken, seqValues);
                            iState = 0;
                        }
                        else if(nStr.StartsWith('['))
                        {
                            seqValues[0] = nStr;
                        }
                        else
                        {
                            if (string.IsNullOrWhiteSpace(seqValues[1]))
                            {
                            seqValues[1] = nStr;
                            }
                            else
                            {
                                if (string.IsNullOrWhiteSpace(seqValues[2]))
                                {
                                    seqValues[2] = nStr;

                                }
                                else
                                {
                                    seqValues[2] = seqValues[2] + " " + nStr;

                                }
                            }

                        }

                        break;

                    case 6:
                        break;

                    default:
                        break;
                }
                res[0] = "Initial load succeeded";
            }

            return res;

        }

    }
    public class CddlState
    {
        public int IState;
        public string Label;
        public string CType;
        public DynamicDictionary CDict;
    }
}
