using System;
using System.IO;
using System.Linq;
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
         
        public string ReadAsJson(string cName, string schema)
        {
            string json;

            var parts = ReadPemParts();
            var decoder = new DefaultDerAsnDecoder();
            // add in as many buckets as needed by the certs.
            int i = 3;
            while (i > -1)
            {
                DerAsnIdentifier identifier = new DerAsnIdentifier(DerAsnTagClass.ContextSpecific, DerAsnEncodingType.Constructed, i);
                DefaultDerAsnDecoder defaultDerAsnDecoder = decoder.RegisterType(identifier, (decoder, identifier, data) => new DerAsnContext(decoder, identifier, data));
                i--;
            }

            byte[] derData = Convert.FromBase64String(parts.Body);
            var der = decoder.Decode(derData);
            if (der == null) throw new ArgumentNullException(nameof(der));
            var sequence = der as DerAsnContext;
            if (sequence == null) throw new ArgumentException($"{nameof(der)} is not a sequence");
            json = SequenceAsJson(sequence);
            return "{\"" + parts.Format + "\":" + json + "}";
        }
        public string SequenceAsJson(DerAsnContext das)
        {
            if (das == null) return "{null}";
            StringBuilder seqStr = new StringBuilder();
            int i = 0; int cnt = das.Value.Length;
            string foo = "";
            while (i < cnt)
            {
                DerAsnType dat = das.Value[i];
                if (i > 0) seqStr.Append(",");
                seqStr.Append(ElementAsJson(dat));
                foo = seqStr.ToString();
                i++;
            }
            return "{" + seqStr.ToString() + "}";
        }
        public string ElementAsJson(DerAsnType dat)
        {
            var res = dat.Value;
            string selectType = dat.GetType().Name;
            string json = "error with type " + selectType;

            if (selectType == "DerAsnBoolen")            //type x01
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
                string seq = SequenceAsJson(dat as DerAsnContext);
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
                int[] values = dat.Value as int[];
                StringBuilder seq = new StringBuilder();
                foreach (int iv in values)
                {
                    if (seq.Length > 0) { seq.Append("."); }
                    seq.Append(iv.ToString());
                }
                return "\"oid\":\"" + seq.ToString() + "\"";
            }
            else if (selectType == "DerAsnSequence")   //type x10
            {
                string seq = SequenceAsJson(dat as DerAsnContext);
                return "\"seq\":" + seq;
            }
            else if (selectType == "DerAsnSet")       //type x11
            {
                string seq = SequenceAsJson(dat as DerAsnContext);
                return "\"set\":" + seq;
            }
            else if (selectType == "DerAsnContext")   //type xA0 A1 A2 A3
            {
                string seq = SequenceAsJson(dat as DerAsnContext);
                return "\"context\":" + seq;
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
