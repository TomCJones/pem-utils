// DerAsnContext to handle methods for certificateas  (c) 2021  tomjones
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DerConverter.Asn;

namespace PemUtils
{
    class DerAsnContext : DerAsnType<DerAsnType[]>
    { 
        public DerAsnContext(IDerAsnDecoder decoder, DerAsnIdentifier identifier, Queue<byte> rawData)
            : base(decoder, identifier, rawData)
        {
        }

        public DerAsnContext(DerAsnIdentifier identifier, DerAsnType[] value)
            : base(identifier, value)
        {
        }

        public DerAsnContext(DerAsnType[] value)
            : base(DerAsnIdentifiers.Constructed.Sequence, value)
        {
        }

        protected override DerAsnType[] DecodeValue(IDerAsnDecoder decoder, Queue<byte> rawData)
        {
            var items = new List<DerAsnType>();
            while (rawData.Any()) items.Add(decoder.Decode(rawData));
            return items.ToArray();
        }

        protected override IEnumerable<byte> EncodeValue(IDerAsnEncoder encoder, DerAsnType[] value)
        {
            return value
                .Select(x => encoder.Encode(x))
                .SelectMany(x => x)
                .ToArray();
        }
    }
}
