using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
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
        private Stack<CddlState> stateStack = new Stack<CddlState>();
        public CddlHandler(string cName, string rawSchema)
        {
            _Name = cName;
            _RawSchema = rawSchema;
        }
        public string[] InitalLoad()
        {
            string[] res = new string[] { "Intial Load failed" };
            // the following is a finite state machine in the context of the finite input string.
            // The state is composed of the iState, cType, label and push down stack of those 3 values.
            int iState = 0;
            string cType = "";
            string label = "";
            string[] iArray = _RawSchema.AsnSplit();  //the input string split into symbols
            Object o = & entry;
            DynamicDictionary currentDict = entry;

            foreach (string nStr in iArray.Where(i => !string.IsNullOrWhiteSpace(i)))
            {
                switch (iState)
                {
                    case 0:  // initial state
                        if (nStr.StringType() == 19)
                        {
                            label = nStr;
                            iState = 1;
                        }
                        break;

                    case 1:
                        if (nStr == "::=")           // is the label being equated to something?
                        {
                            iState = 2;
                        }
                        else if (nStr ==  "BIT")
                        {
                            iState = 99;            // This is probably a BIT STRING - wait for next symbol
                        }
                        else if (nStr.StringType() == 19)  // is the label pointing to a class?
                        {
                            // add to the current dictionary at this point in the stack
                            iState = 0;
                        }
                        break;

                    case 2:
                        cType = nStr;
                        iState = 3;
                        break;

                    case 3:                          // "{" starts the creation of a new dd entry
                        // TODO push the current state until poped with a "}"  ===  also do we need a type "SEQUENCE" in dd?
                        o = Activator.CreateInstance(typeof(DynamicDictionary));
                        CddlState nextPush = new CddlState()
                        {
                            IState = iState,
                            Label = label,
                            CType = cType,
                            CDict = currentDict
                        };
                        stateStack.Push(nextPush);
                        entry.Add(label, o);   // initially points to entry in main dictionary
                        iState = 0;
                        break;
                    case 4:
                        break;

                    default:
                        break;
                }
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
