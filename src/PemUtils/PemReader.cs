using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using DerConverter;
using DerConverter.Asn;
using DerConverter.Asn.KnownTypes;
using PemUtils.Models;

namespace PemUtils
{
    public class PemReader : IDisposable
    {
        private static readonly int[] RsaIdentifier = new[] { 1, 2, 840, 113549, 1, 1, 1 };  //  TODO move to csv file
        private readonly Stream _stream;
        private readonly bool _disposeStream;
        private Encoding _encoding;
        private CddlHandler _cddl;
        protected DefaultDerAsnDecoder _decoder = null;
        protected string lastOID = "";
        public static Func<IDerAsnDecoder> ExpandedDecoder { get; set; } = () => new DefaultDerAsnDecoder();
        //   protected ExpandedDecoder decoder;

        public PemReader(Stream stream, bool disposeStream = false, Encoding encoding = null)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _disposeStream = disposeStream;
            _encoding = encoding ?? Encoding.UTF8;
            if (ExpandedDecoder == null) throw new ArgumentNullException(nameof(ExpandedDecoder));
            //       var decoder = ExpandedDecoder();
            //      decoder.RegisterType(DerAsnEncodingType.Constructed, DerAsnKnownTypeTags.Constructed.Sequence, (decoder, identifier, data) => new DerAsnSequence(decoder, identifier, data));
        }

        public void Dispose()
        {
            if (_disposeStream) _stream.Dispose();
        }

        public string ReadAsJson(string cName, CddlHandler cddl)
        {
            _cddl = cddl;
            string json;

            var parts = ReadPemParts();
            if (_decoder == null)
            {
             _decoder = new DefaultDerAsnDecoder();

            }

            // add in as many buckets as needed by the certs to the decode (will be A0, A1, A2, A3).  // this is a kludge will a general soluition is architected
            int i = 3;
            while (i > -1)
            {
                DerAsnIdentifier identifier = new DerAsnIdentifier(DerAsnTagClass.ContextSpecific, DerAsnEncodingType.Constructed, i);
                DefaultDerAsnDecoder defaultDerAsnDecoder = _decoder.RegisterType(identifier, (decoder, identifier, data) => new DerAsnContext(decoder, identifier, data));
                i--;
            }

            // get name of schema to be used from the CddlHandler
            var cddlEnum = cddl.entry.GetEnumerator();
            cddlEnum.MoveNext();
            string cddlTitle = cddlEnum.Current.Key;
            object cddlValue = cddlEnum.Current.Value;

            byte[] derData = Convert.FromBase64String(parts.Body);
            var der = _decoder.Decode(derData);
            if (der == null) throw new ArgumentNullException(nameof(der));
            var sequence = der as DerAsnContext;
            if (sequence == null) throw new ArgumentException($"{nameof(der)} is not a sequence");
            json = SequenceAsJson(sequence, cddlTitle, cddlValue);
            return "{\"certificate\":{" + json ;

        }

        public string SequenceAsJson(DerAsnContext das, string oName, object oValue)
        {
            if (das == null) return "{null}";
            int cntDict = 0;
            List<string> namesDict = new List<string>();
            List<string[]> valuesDict = new List<string[]>();
            if (oValue is IDictionary)
            {
                cntDict = (oValue as Dictionary<string, string[]>).Count;
                namesDict = (oValue as Dictionary<string, string[]>).Keys.ToList<string>();
                valuesDict = (oValue as Dictionary<string, string[]>).Values.ToList<string[]>();
            }
            StringBuilder seqStr = new StringBuilder();   // creating a new sequence without a beginning "{"
            int i = 0;
            int cnt = das.Value.Length;
            string tName = "";
            string[] tValue = null;
            long lTag;
            DerAsnType[] res = null;

            string testStr = valuesDict[0][0].Trim();

            if (cntDict > 0 && testStr == "CHOICE")   // can be effectively ignored
            {
                DerAsnType datx = das.Value[i];
                lTag = datx.Identifier.Tag;
                if (valuesDict[1][0] == "SEQUENCE OF")
                {
                    string nextName = valuesDict[1][1];             // these are reuse for each entry in the sequence
                    string nextValues = _cddl.entry[nextName] as string;
                    List<DerAsnType> seqDict = das.Value.ToList<DerAsnType>();
                    if (nextValues.Trim().StartsWith("SET OF"))
                    {
                        string n2Name = nextValues.Substring(6).Trim();
                        Dictionary<string, string[]> n2Value = _cddl.entry[n2Name] as Dictionary<string, string[]>;
                        long c2Dict = n2Value.Count;
                        List<string> n2Dict = n2Value.Keys.ToList<string>();
                        List<string[]> v2Dict = n2Value.Values.ToList<string[]>();
                        foreach (DerAsnType dat in seqDict)
                        {
                            if (n2Dict[0] == "_TYPE" && n2Dict[1] == "type" && n2Dict[2] == "value")
                            {
                                string typeSTR = v2Dict[1][1];
                                string valueStr = v2Dict[2][1];
                                res = (DerAsnType[])dat.Value;                          // null reference set to null
                                string subType = res[0]?.GetType()?.Name;
                                DerAsnType[] daa = res[0]?.Value as DerAsnType[];
                                string sea = "{" + SequenceAsJson(res[0] as DerAsnContext, n2Name, n2Value);
                                AttributeTypeAndValue resp = JsonSerializer.Deserialize<AttributeTypeAndValue>(sea);
                                string fubar = n2Name;
                                if (seqStr.Length > 1) { seqStr.Append(","); }
                                seqStr.Append("\"" + resp.type + "\":\"" + resp.printablestring + "\"");
                            }
                        }
                        return  seqStr.ToString() + "}" ;
                    }
                    else
                    {
                        throw new Exception("Expected SET OF, found " + nextValues);
                    }
                }

                return seqStr.ToString() + "}";
            }

            if (cntDict > 0)  //  TODO get env if not production  --   add the type element to the json for debug only
            {
                string[] typeStr = valuesDict[0];
                string type0 = typeStr[0];
                seqStr.Append("\"_type\":\"" + type0.Trim() + "\",");
            }

            while (i < cnt)                  //
            {
                DerAsnType dat = das.Value[i];
                lTag = dat.Identifier.Tag;
                if (i > 0) seqStr.Append(",");
                i++;
                tName = "empty";
                try
                {
                    if (cntDict >= i) { tName = namesDict[i]; tValue = valuesDict[i]; }
                }
                catch (Exception ex)
                {
                    throw new Exception("Sequencing to JSON, cannot read names for valudes from dictionary " + ex.Message);
                }
                if (tValue != null && tValue[2] == "OPTIONAL")  // Optional elements are all at the end of the sequence
                {
                    int j = i;
                    //  test if current one is in the input
                    string contextIndex = tValue[0].TrimStart('[').TrimEnd(']');
                    try
                    {
                        long indx = int.Parse(contextIndex);
                        while (indx != lTag)
                        {
                            j++;
                            tName = "empty";
                            if (cntDict >= j) { tName = namesDict[j]; tValue = valuesDict[j]; }
                            contextIndex = tValue[0].TrimStart('[').TrimEnd(']');
                            indx = int.Parse(contextIndex);
                        }
                    }
                    catch (Exception ex)
                    {
                        throw new Exception("Error handing OPTIONAL elements " + oName + " Exception = " + ex.Message);
                    }
                    string plicit = "EXPLICIT";
                    string nextName = "";
                }
                seqStr.Append(ElementAsJson(dat, tName, tValue));
                tName = "";
            }
            return seqStr.ToString() + "}";
        }
        public string ElementAsJson(DerAsnType dat, string oName, object oValue)
        {
            DerAsnType[] res = null;
            long lTag;
            string[] sValue;
            bool bRet = false;
            string selectType = dat?.GetType()?.Name;
            string json = "error with type " + selectType;
            try
            {
                if (dat != null)
                {
                    if (selectType == "DerAsnInteger")
                    {
                        object nValue = dat.Value;                          // null reference set to null
                        BigInteger biRes = (BigInteger)nValue;
                        byte[] byteRes = biRes.ToByteArray();

                        return "\"" + oName + "\":" + biRes.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("expected [integer] for exception " + ex.Message);
            }
            DerAsnTagClass datc = dat.Identifier.TagClass;
            sValue = oValue as string[];
            lTag = dat.Identifier.Tag;
            if (datc == DerAsnTagClass.ContextSpecific)
            {
                string contextIndex = sValue[0].TrimStart('[').TrimEnd(']');
                string plicit = "EXPLICIT";
                string nextName = "";
                res = (DerAsnType[])dat.Value;                          // null reference set to null
                try
                {
                    long indx = int.Parse(contextIndex);
                    string[] nextObj = sValue[1].Split(' ');  //  should be xxPLICIT next name
                    nextName = plicit = nextObj[0];           // there might be cases where "EXPLICIT" is omitted
                    if (!string.IsNullOrWhiteSpace(nextObj[1])) { nextName = nextObj[1]; }
                    if (lTag == indx)                         // is this the context specific tag that we are parsing?
                    {
                        bRet = _cddl.entry.TryGetValue(nextName, out object nValue);
                        BigInteger biRet = 0;
                        DerAsnType dat0 = res[0];
                        string getType = dat0.GetType().Name;
                        if (res[0].GetType().Name == "DerAsnInteger")
                        {
                            biRet = (res[0] as DerAsnInteger).Value;
                            return "\"" + nextName + "\":" + biRet.ToString();   //  TODO add base64 encoding
                        }
                        //                string seq = ElementAsJson(res[0], nextName, nValue);
                        return "\"" + oName + "\":" + biRet.ToString();
                    }
                    else                                       // if not and this is optional try the next schema entry
                    {

                    }
                }
                catch (Exception ex)
                {
                    throw new Exception("expected [integer] in context-specific key, found " + sValue[0]);
                }
            }
            else if (selectType == "DerAsnBoolen")            //type x01
            {
                byte[] ba = new byte[1] { 0 };            // to avoid null condition
                var bValue = dat.Value as DerAsnBoolean;     // TODO - actually check value
                return "\"bool\":\"false\"";
            }
            else if (selectType == "DerAsnInteger")       //type x02
            {
                byte[] ba = new byte[1] { 0 };            // to avoid null condition
                var dai = dat.Value as DerAsnInteger;     // this is nullable while int is not
                if (dai != null) { ba = GetIntegerData(dat.Value as DerAsnInteger); }
                long intBin = 0;                          // careful to avoid leading zeros. 
                try { intBin = BitConverter.ToInt64(ba); } catch { };  // just ignore overflow
                string intStr = intBin.ToString();
                return "\"int\":" + intStr;
            }
            else if (selectType == "DerAsnBitString")    //type x03
            {
                BitArray dabs = dat.Value as BitArray;
                int baCnt = dabs.Length;
                string seq = "byte array not divisible by 8, or was empty";
                byte[] reversed = new byte[1] { 0 } ;
                if (baCnt > 0 && baCnt % 8 == 0)
                {
                    int byteCnt = baCnt / 8;
                    byte[] byteArray = new byte[byteCnt];
                    dabs.CopyTo(byteArray, 0);
                    if (oName == "subjectPublicKey")
                    {
                        reversed = byteArray.Reverse().ToArray();
                        DerAsnContext der = _decoder.Decode(reversed) as DerAsnContext;
                        string rsaOID = OID2String(RsaIdentifier);
                        string spkName = "RSAPublicKey";
                        Dictionary<string, string[]> spkDict = _cddl.entry[spkName];
                        if (lastOID == rsaOID)
                        {
                            seq = "{" + SequenceAsJson(der, spkName, spkDict) + "}";
                            return "\"" + spkName + "\":" + seq;
                        }
                        else
                        {
                            seq = "\"" + BitConverter.ToString(reversed) + "\"";    //  this converts to hex --  might want base64url?
                        }
                    }
                    else
                    {
                        seq = "\"" + BitConverter.ToString(byteArray) + "\"";    //  this converts to hex --  might want base64url?
                    }
                }
                return "\"" + oName + "\":" + seq  ;
            }
            else if (selectType == "DerAsnOctetString")   //type x04
            {
                byte[] octStr = dat.Value as byte[];
                string hexStr = BitConverter.ToString(octStr);    //  this converts to hex --  might want base64url?
                return "\"octet\":\"" + hexStr + "\"";
            }
            else if (selectType == "DerAsnNull")           //type x05
            {
                return "\"" + oName + "\":\"null\"";
            }
            else if (selectType == "DerAsnObjectIdentifier")   //type x06
            {
                StringBuilder seq = new StringBuilder(40);    // long enuf for an OID of 20 integers
                string seqStr = "";
                try
                {
                    int[] values = dat.Value as int[];
                    foreach (int iv in values)
                    {
                        if (seq.Length > 0) { seq.Append("."); }
                        seq.Append(iv.ToString());
                    }
                    lastOID = seq.ToString();                 // must convert SB to string before passing the string to a function
                    seqStr = "\"" + oName + "\":\"" + lastOID; 
                }
                catch (Exception ex)
                {
                    return "\"" + oName + "\":\"" + " String Builder Exception: " + ex.Message + "\"";
                }

                return seqStr + "\"";
            }
            else if (selectType == "DerAsnSequence")   //type x10
            {
                string seq = SequenceAsJson(dat as DerAsnContext, oName, oValue);
                return "\"seq\":" + seq;
            }
            else if (selectType == "DerAsnSet")       //type x11
            {
                string qualifier = (oValue as string[])[0];
                if (qualifier == "SEQUENCE OF")
                {
                    string nextName = (oValue as string[])[1];
                    string nextValue = _cddl.entry[nextName].ToString();
                    if (nextValue.StartsWith("SET OF"))
                    {
                        string n2Name = nextValue.Substring(6).Trim();
                        Dictionary<string, string[]> n2Value = _cddl.entry[n2Name];
                        long c2Dict = n2Value.Count;
                        List<string> n2Dict = n2Value.Keys.ToList<string>();
                        List<string[]> v2Dict = n2Value.Values.ToList<string[]>();
                        if (n2Dict[0] == "_TYPE" && n2Dict[1] == "type" && n2Dict[2] == "value")
                        {
                            string typeSTR = v2Dict[1][1];
                            string valueStr = v2Dict[2][1];
                            res = (DerAsnType[])dat.Value;                          // null reference set to null
                            string subType = res[0]?.GetType()?.Name;
                            DerAsnType[] daa = res[0]?.Value as DerAsnType[];
                            string sea = "{" + SequenceAsJson(res[0] as DerAsnContext, n2Name, n2Value);
                            AttributeTypeAndValue resp = JsonSerializer.Deserialize<AttributeTypeAndValue>(sea);
                            return "\"" + resp.type + "\":\"" + resp.printablestring + "\"";
                        }
                        string fubar = n2Name;
                    }
                }
                string seq = SequenceAsJson(dat as DerAsnContext, oName, oValue);
                return seq;
            }
            else if (selectType == "DerAsnContext")   //type xA0 A1 A2 A3
            {
                string nName = (oValue as string[])[1];
                bRet = _cddl.entry.TryGetValue(nName, out object nValue);
                string seq = SequenceAsJson(dat as DerAsnContext, nName, nValue);
                return "\"" + oName + "\":{" + seq;
            }
            else if (selectType == "DerAsnUtcTime")
            {
                DerAsnUtcTime daut = dat as DerAsnUtcTime;
                DateTimeOffset dto = daut.Value;
                return "\"" + oName + "\":\"" + dto.ToString() + "\"";
            }
            else if (selectType == "DerAsnBoolean")
            {
                DerAsnBoolean b = dat as DerAsnBoolean;
                bool dto = b.Value;
                return "\"boolean\":" + dto.ToString();
            }
            else if (selectType == "DerAsnPrintableString")
            {
                DerAsnPrintableString daps = dat as DerAsnPrintableString;
                string dts = daps.Value;
                return "\"printablestring\":\"" + dts + "\"";
            }

            return json;
        }

        public RSAParameters ReadRsaKey()
        {
            var parts = ReadPemParts();
            byte[] derData = Convert.FromBase64String(parts.Body);
            var der = DerConvert.Decode(derData);

            if (parts.Format.Equals(PemFormat.Public._type)) return ReadPublicKey(der);
            string strRsa = PemFormat.Rsa._type; ;
            if (parts.Format.Equals(PemFormat.Rsa._type)) return ReadRSAPrivateKey(der);
            string str1 = parts.Format;
            string str2 = PemFormat.Private._type;
            if (parts.Format.Equals(PemFormat.Private._type)) return ReadPrivateKey(der);
            throw new NotImplementedException($"The format {parts.Format} is not yet implemented");
        }

        private PemParts ReadPemParts()
        {
            using (var reader = new StreamReader(_stream, _encoding, true, 4096, true))
            {
                PemParts parts = ExtractPemParts(reader.ReadToEnd());
                var headerFormat = ExtractFormat(parts.Header, isFooter: false);
                var footerFormat = ExtractFormat(parts.Footer, isFooter: true);
                string format = headerFormat._type;
                parts.Format = format;
                if (!headerFormat.Equals(footerFormat))
                    throw new InvalidOperationException($"Header/footer format mismatch: {headerFormat}/{footerFormat}");
                return parts;
            }

        }

        private static PemParts ExtractPemParts(string pem)
        {
            var match = Regex.Match(pem, @"^(?<header>\-+\s?BEGIN[^-]+\-+)\s*(?<body>[^-]+)\s*(?<footer>\-+\s?END[^-]+\-+)\s*$");
            if (!match.Success)
                throw new InvalidOperationException("Data on the stream doesn't match the required PEM format");
            return new PemParts
            {
                Header = match.Groups["header"].Value,
                Body = match.Groups["body"].Value.RemoveWhitespace(),
                Footer = match.Groups["footer"].Value
            };
        }

        private static PemFormat ExtractFormat(string headerOrFooter, bool isFooter)
        {
            var beginOrEnd = isFooter ? "END" : "BEGIN";
            var match = Regex.Match(headerOrFooter, $@"({beginOrEnd})\s+(?<format>[^-]+)", RegexOptions.IgnoreCase);
            if (!match.Success)
                throw new InvalidOperationException($"Unrecognized {beginOrEnd}: {headerOrFooter}");
            return PemFormat.Parse(match.Groups["format"].Value.Trim());
        }

        private static RSAParameters ReadPublicKey(DerAsnType der)
        {
            if (der == null) throw new ArgumentNullException(nameof(der));
            var outerSequence = der as DerAsnContext;
            if (outerSequence == null) throw new ArgumentException($"{nameof(der)} is not a sequence");
            if (outerSequence.Value.Length != 2) throw new InvalidOperationException("Outer sequence must contain 2 parts");

            var headerSequence = outerSequence.Value[0] as DerAsnContext;
            if (headerSequence == null) throw new InvalidOperationException("First part of outer sequence must be another sequence (the header sequence)");
            if (headerSequence.Value.Length != 2) throw new InvalidOperationException("The header sequence must contain 2 parts");
            var objectIdentifier = headerSequence.Value[0] as DerAsnObjectIdentifier;
            if (objectIdentifier == null) throw new InvalidOperationException("First part of header sequence must be an object-identifier");
            if (!Enumerable.SequenceEqual(objectIdentifier.Value, RsaIdentifier)) throw new InvalidOperationException($"RSA object-identifier expected 1.2.840.113549.1.1.1, got: {string.Join(".", objectIdentifier.Value.Select(x => x.ToString()))}");
            if (!(headerSequence.Value[1] is DerAsnNull)) throw new InvalidOperationException("Second part of header sequence must be a null");

            var innerSequenceBitString = outerSequence.Value[1] as DerAsnBitString;
            if (innerSequenceBitString == null) throw new InvalidOperationException("Second part of outer sequence must be a bit-string");

            var innerSequenceData = innerSequenceBitString.ToByteArray();
            var innerSequence = DerConvert.Decode(innerSequenceData) as DerAsnContext;
            if (innerSequence == null) throw new InvalidOperationException("Could not decode the bit-string as a sequence");
            if (innerSequence.Value.Length < 2) throw new InvalidOperationException("Inner sequence must at least contain 2 parts (modulus and exponent)");

            return new RSAParameters
            {
                Modulus = GetIntegerData(innerSequence.Value[0]),
                Exponent = GetIntegerData(innerSequence.Value[1])
            };
        }

        private static RSAParameters ReadPrivateKey(DerAsnType der)
        {
            if (der == null) throw new ArgumentNullException(nameof(der));
            var sequence = der as DerAsnContext;
            if (sequence == null) throw new ArgumentException($"{nameof(der)} is not a sequence");
            if (sequence.Value.Length != 9) throw new InvalidOperationException("Sequence must contain 9 parts");
            return new RSAParameters
            {
                Modulus = GetIntegerData(sequence.Value[1]),
                Exponent = GetIntegerData(sequence.Value[2]),
                D = GetIntegerData(sequence.Value[3]),
                P = GetIntegerData(sequence.Value[4]),
                Q = GetIntegerData(sequence.Value[5]),
                DP = GetIntegerData(sequence.Value[6]),
                DQ = GetIntegerData(sequence.Value[7]),
                InverseQ = GetIntegerData(sequence.Value[8]),
            };
        }
        private static RSAParameters ReadRSAPrivateKey(DerAsnType der)
        {
            if (der == null) throw new ArgumentNullException(nameof(der));
            var sequence = der as DerAsnContext;
            if (sequence == null) throw new ArgumentException($"{nameof(der)} is not a sequence");
            if (sequence.Value.Length != 9) throw new InvalidOperationException("Sequence must contain 9 parts");
            return new RSAParameters
            {
                Modulus = GetIntegerData(sequence.Value[1]),
                Exponent = GetIntegerData(sequence.Value[2]),
                D = GetIntegerData(sequence.Value[3]),
                P = GetIntegerData(sequence.Value[4]),
                Q = GetIntegerData(sequence.Value[5]),
                DP = GetIntegerData(sequence.Value[6]),
                DQ = GetIntegerData(sequence.Value[7]),
                InverseQ = GetIntegerData(sequence.Value[8]),
            };
        }

        private static byte[] GetIntegerData(DerAsnType der)
        {
            var data = (der as DerAsnInteger)?.Encode(null);
            if (data == null) throw new InvalidOperationException("Part does not contain integer data");
            if (data[0] == 0x00) data = data.Skip(1).ToArray();
            return data;
        }

        private class PemParts
        {
            public string Header { get; set; }
            public string Body { get; set; }
            public string Footer { get; set; }
            public string Format { get; set; }   //tcj
        }

    public string OID2String(int[] bytesIn)
    {
        StringBuilder seq = new StringBuilder(40);    // long enuf for an OID of 20 integers
        string seqStr = "";
        try
        {
            foreach (int iv in bytesIn)
            {
                if (seq.Length > 0) { seq.Append("."); }
                seq.Append(iv.ToString());
            }
            seqStr = seq.ToString();                 // must convert SB to string before passing the string to a function
            return seqStr;
        }
        catch (Exception ex)
        {
            return " String Builder Exception: " + ex.Message + "\"";
        }
    }    }
}
