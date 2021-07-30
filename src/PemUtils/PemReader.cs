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

namespace PemUtils
{
    public class PemReader : IDisposable
    {
        private static readonly int[] RsaIdentifier = new[] { 1, 2, 840, 113549, 1, 1, 1 };
        private readonly Stream _stream;
        private readonly bool _disposeStream;
        private Encoding _encoding;
        private CddlHandler _cddl;
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
            var decoder = new DefaultDerAsnDecoder();
            // add in as many buckets as needed by the certs to the decode (will be A0, A1, A2, A3).  // this is a kludge will a general soluition is architected
            int i = 3;
            while (i > -1)
            {
                DerAsnIdentifier identifier = new DerAsnIdentifier(DerAsnTagClass.ContextSpecific, DerAsnEncodingType.Constructed, i);
                DefaultDerAsnDecoder defaultDerAsnDecoder = decoder.RegisterType(identifier, (decoder, identifier, data) => new DerAsnContext(decoder, identifier, data));
                i--;
            }

            // get name of schema to be used from the CddlHandler
            var cddlEnum = cddl.entry.GetEnumerator();
            cddlEnum.MoveNext();
            string cddlTitle = cddlEnum.Current.Key;
            object cddlValue = cddlEnum.Current.Value;

            byte[] derData = Convert.FromBase64String(parts.Body);
            var der = decoder.Decode(derData);
            if (der == null) throw new ArgumentNullException(nameof(der));
            var sequence = der as DerAsnContext;
            if (sequence == null) throw new ArgumentException($"{nameof(der)} is not a sequence");
            json = SequenceAsJson(sequence, cddlTitle, cddlValue);
            return json;
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
            StringBuilder seqStr = new StringBuilder("{\"" + oName + "\":");
            int i = 0;
            int cnt = das.Value.Length;
            string tName = "";
            string[] tValue = null;
            if (cntDict>0)  //  TODO get env if not production  --   add the type element to the json for debug only
            {
                string[] typeStr = valuesDict[0];
                string type0 = typeStr[0];
                seqStr.Append("\"_type\":\"" + type0 + "\",");
            }
            long lTag;
            while (i < cnt)                  // TODO for optional we need to advance
            {
                DerAsnType dat = das.Value[i];
                lTag = dat.Identifier.Tag;
                if (i > 0) seqStr.Append(",");
                i++;
                tName = "empty";
                if (cntDict >= i) { tName = namesDict[i]; tValue = valuesDict[i]; }
                if (tValue != null  &&  tValue[2] == "OPTIONAL")  // Optional elements are all at the end of the sequence
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

                    

                    if (selectType ==  "DerAsnInteger")
                    {
                        object nValue = dat.Value;                          // null reference set to null
                        BigInteger biRes = (BigInteger) nValue ;
                        byte[] byteRes = biRes.ToByteArray();

                        return "{\"" + oName + "\":" + biRes.ToString();
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
                            return "\""+ nextName + "\":" + biRet.ToString();   //  TODO add base64 encoding
                        }
                        //                string seq = ElementAsJson(res[0], nextName, nValue);
                        return "{\"" + oName + "\":" + biRet.ToString();
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
                string seq = SequenceAsJson(dat as DerAsnContext, oName, oValue);
                return "\"bitstring\":" + seq.Replace('-', ':');
            }
            else if (selectType == "DerAsnOctetString")   //type x04
            {
                byte[] octStr = dat.Value as byte[];
                string hexStr = BitConverter.ToString(octStr);    //  this converts to hex --  might want base64url?
                return "\"octet\":\"" + hexStr + "\"";
            }
            else if (selectType == "DerAsnNull")           //type x05
            {
                return "\"null\":0";
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
                    seqStr = "\"" + oName + "\":\"" + seq.ToString(); // must convert SB to string befor passing the string to a function
                }
                catch (Exception ex)
                {
                    return "\"" + oName + "\":\"" + " String Builder Exception: " + ex.Message + "\"";
                }

                return  seqStr + "\"";
            }
            else if (selectType == "DerAsnSequence")   //type x10
            {
                string seq = SequenceAsJson(dat as DerAsnContext, oName, oValue);
                return "\"seq\":" + seq;
            }
            else if (selectType == "DerAsnSet")       //type x11
            {
                string seq = SequenceAsJson(dat as DerAsnContext, oName, oValue);
                return "\"set\":" + seq;
            }
            else if (selectType == "DerAsnContext")   //type xA0 A1 A2 A3
            {
                string nName = (oValue as string[])[1];
                bRet = _cddl.entry.TryGetValue(nName, out object nValue);
                string seq = SequenceAsJson(dat as DerAsnContext, nName, nValue);
                return "{\"" + oName + "\":" + seq;
            }
            else if (selectType == "DerAsnUtcTime")
            {
                DerAsnUtcTime daut = dat as DerAsnUtcTime;
                DateTimeOffset dto = daut.Value;
                return "\"date_time\":" + dto.ToString();
            }
            else if (selectType == "DerAsnBoolean")
            {
                DerAsnBoolean b = dat as DerAsnBoolean;
                bool dto = b.Value;
                return "\"boolean\":" + dto.ToString();
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
                if (!headerFormat.Equals(footerFormat)) throw new InvalidOperationException($"Header/footer format mismatch: {headerFormat}/{footerFormat}");

                return parts;
            }

        }

        private static PemParts ExtractPemParts(string pem)
        {
            var match = Regex.Match(pem, @"^(?<header>\-+\s?BEGIN[^-]+\-+)\s*(?<body>[^-]+)\s*(?<footer>\-+\s?END[^-]+\-+)\s*$");
            if (!match.Success) throw new InvalidOperationException("Data on the stream doesn't match the required PEM format");

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
            if (!match.Success) throw new InvalidOperationException($"Unrecognized {beginOrEnd}: {headerOrFooter}");
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
    }
}
