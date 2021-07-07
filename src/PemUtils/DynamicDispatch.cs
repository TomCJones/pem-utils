using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;

namespace PemUtils
{
    class DynamicDispatch
    {
    }
    // see https://www.codeproject.com/Articles/203453/DynMethodDispatcher
    public abstract class DynMethodDispatcherBase<KEY, MESSAGE, RETURN>
    {
        public delegate RETURN DynMethod(KEY key, MESSAGE message);

        internal protected Dictionary<KEY, DynMethod> Dictionary =
            new Dictionary<KEY, DynMethod>();
        public int this[KEY key]
        {
            get
            {
                DynMethod method;
                if (Dictionary.TryGetValue(key, out method))
                    return method.GetInvocationList().Length;
                return 0;
            }
        }
        KEY[] Keys
        {
            get
            {
                KEY[] res = new KEY[Dictionary.Keys.Count];
                int i = 0;
                foreach (KEY key in Dictionary.Keys)
                {
                    res[i] = key;
                    ++i;
                }
                return res;
            }
        }
        internal protected RETURN SingleCastInvoke(KEY key, MESSAGE message)
        {
            DynMethod method;
            if (Dictionary.TryGetValue(key, out method))
                return method.Invoke(key, message);
            throw new DynMethodNotFoundException<KEY, MESSAGE>(key, message);
        }
        internal protected bool SingleCastTryInvoke(KEY key,
                  MESSAGE message, out RETURN returnValue)
        {
            DynMethod method;
            bool success = Dictionary.TryGetValue(key, out method);
            if (success)
                returnValue = method.Invoke(key, message);
            else
                returnValue = default(RETURN);
            return success;
        }
    }
    public class DynMethodDispatcher<KEY, MESSAGE, RETURN> :
             DynMethodDispatcherBase<KEY, MESSAGE, RETURN>
    {
        public bool Add(KEY key, DynMethod method)
        {
            if (Dictionary.ContainsKey(key)) return false;
            Dictionary.Add(key, method);
            return true;
        } //AddReplace
        public RETURN Invoke(KEY key, MESSAGE message)
        { return SingleCastInvoke(key, message); }
        public bool TryInvoke(KEY key, MESSAGE message, out RETURN returnValue)
        { return SingleCastTryInvoke(key, message, out returnValue); }
    }
    public class DynMethodNotFoundException<KEY, MESSAGE> : SystemException
    {
        KEY FKey;
        MESSAGE FMessage;
        internal DynMethodNotFoundException(KEY key, MESSAGE message)
        {
            this.FKey = key; this.FMessage = message;
        }
        public KEY KeyValue { get { return this.FKey; } }
        public MESSAGE MessageValue { get { return this.FMessage; } }
    }
}
